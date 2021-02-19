// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/chromeos/login/version_updater/version_updater.h"

#include <algorithm>
#include <memory>
#include <string>
#include <utility>

#include "base/bind.h"
#include "base/logging.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/default_tick_clock.h"
#include "base/time/time.h"
#include "chrome/browser/chromeos/login/version_updater/update_time_estimator.h"
#include "chrome/grit/chromium_strings.h"
#include "chrome/grit/generated_resources.h"
#include "chromeos/dbus/dbus_thread_manager.h"
#include "chromeos/network/network_state.h"
#include "ui/base/l10n/l10n_util.h"

namespace chromeos {

namespace {

// Time in seconds after which we decide that the device has not rebooted
// automatically. If reboot didn't happen during this interval, ask user to
// reboot device manually.
constexpr const base::TimeDelta kWaitForRebootTime =
    base::TimeDelta::FromSeconds(3);

// Progress bar stages. Each represents progress bar value
// at the beginning of each stage.
// TODO(nkostylev): Base stage progress values on approximate time.
// TODO(nkostylev): Animate progress during each state.
const int kBeforeUpdateCheckProgress = 7;
const int kBeforeDownloadProgress = 14;
const int kBeforeVerifyingProgress = 74;
const int kBeforeFinalizingProgress = 81;
const int kProgressComplete = 100;

// Defines what part of update progress does download part takes.
const int kDownloadProgressIncrement = 60;

// Period of time between planned updates.
constexpr const base::TimeDelta kUpdateTime = base::TimeDelta::FromSeconds(1);

}  // anonymous namespace

VersionUpdater::UpdateInfo::UpdateInfo() {}

VersionUpdater::VersionUpdater(VersionUpdater::Delegate* delegate)
    : delegate_(delegate),
      wait_for_reboot_time_(kWaitForRebootTime),
      tick_clock_(base::DefaultTickClock::GetInstance()) {
  Init();
}

VersionUpdater::~VersionUpdater() {
  DBusThreadManager::Get()->GetUpdateEngineClient()->RemoveObserver(this);
  network_portal_detector::GetInstance()->RemoveObserver(this);
}

void VersionUpdater::Init() {
  time_estimator_ = UpdateTimeEstimator();
  is_first_detection_notification_ = true;
  update_info_ = UpdateInfo();
}

void VersionUpdater::StartNetworkCheck() {
  // If portal detector is enabled and portal detection before AU is
  // allowed, initiate network state check. Otherwise, directly
  // proceed to update.
  if (!network_portal_detector::GetInstance()->IsEnabled()) {
    StartUpdateCheck();
    return;
  }
  update_info_.state = State::STATE_FIRST_PORTAL_CHECK;
  delegate_->UpdateInfoChanged(update_info_);

  is_first_detection_notification_ = true;
  network_portal_detector::GetInstance()->AddAndFireObserver(this);
}

void VersionUpdater::StartUpdateCheck() {
  delegate_->PrepareForUpdateCheck();
  RequestUpdateCheck();
}

void VersionUpdater::SetUpdateOverCellularOneTimePermission() {
  DBusThreadManager::Get()
      ->GetUpdateEngineClient()
      ->SetUpdateOverCellularOneTimePermission(
          update_info_.update_version, update_info_.update_size,
          base::BindOnce(
              &VersionUpdater::OnSetUpdateOverCellularOneTimePermission,
              weak_ptr_factory_.GetWeakPtr()));
}

void VersionUpdater::RejectUpdateOverCellular() {
  // Reset UI context to show curtain again when the user goes back to the
  // screen.
  update_info_.progress_unavailable = true;
  update_info_.requires_permission_for_cellular = false;
  delegate_->UpdateInfoChanged(update_info_);
}

void VersionUpdater::RebootAfterUpdate() {
  VLOG(1) << "Initiate reboot after update";
  DBusThreadManager::Get()->GetUpdateEngineClient()->RebootAfterUpdate();
  if (wait_for_reboot_time_.is_zero())  // Primarily for testing.
    OnWaitForRebootTimeElapsed();
  else
    reboot_timer_.Start(FROM_HERE, wait_for_reboot_time_, this,
                        &VersionUpdater::OnWaitForRebootTimeElapsed);
}

void VersionUpdater::StartExitUpdate(Result result) {
  DBusThreadManager::Get()->GetUpdateEngineClient()->RemoveObserver(this);
  network_portal_detector::GetInstance()->RemoveObserver(this);
  delegate_->FinishExitUpdate(result);
  // Reset internal state, because in case of error user may make another
  // update attempt.
  Init();
}

base::OneShotTimer* VersionUpdater::GetRebootTimerForTesting() {
  return &reboot_timer_;
}

void VersionUpdater::GetEolInfo(EolInfoCallback callback) {
  UpdateEngineClient* update_engine_client =
      DBusThreadManager::Get()->GetUpdateEngineClient();
  // Request the End of Life (Auto Update Expiration) status. Bind to a weak_ptr
  // bound method rather than passing |callback| directly so that |callback|
  // does not outlive |this|.
  update_engine_client->GetEolInfo(
      base::BindOnce(&VersionUpdater::OnGetEolInfo,
                     weak_ptr_factory_.GetWeakPtr(), std::move(callback)));
}

void VersionUpdater::OnGetEolInfo(EolInfoCallback callback,
                                  UpdateEngineClient::EolInfo info) {
  std::move(callback).Run(std::move(info));
}

void VersionUpdater::UpdateStatusChangedForTesting(
    const update_engine::StatusResult& status) {
  UpdateStatusChanged(status);
}

void VersionUpdater::RequestUpdateCheck() {
  update_info_.state = State::STATE_UPDATE;
  update_info_.progress = kBeforeUpdateCheckProgress;
  update_info_.update_version = std::string();
  update_info_.update_size = 0;
  delegate_->UpdateInfoChanged(update_info_);

  network_portal_detector::GetInstance()->RemoveObserver(this);
  DBusThreadManager::Get()->GetUpdateEngineClient()->AddObserver(this);
  VLOG(1) << "Initiate update check";
  DBusThreadManager::Get()->GetUpdateEngineClient()->RequestUpdateCheck(
      base::BindOnce(&VersionUpdater::OnUpdateCheckStarted,
                     weak_ptr_factory_.GetWeakPtr()));
}

void VersionUpdater::UpdateStatusChanged(
    const update_engine::StatusResult& status) {
  update_info_.status = status;

  if (update_info_.is_checking_for_update &&
      status.current_operation() >
          update_engine::Operation::CHECKING_FOR_UPDATE &&
      status.current_operation() != update_engine::Operation::ERROR &&
      status.current_operation() !=
          update_engine::Operation::REPORTING_ERROR_EVENT) {
    update_info_.is_checking_for_update = false;
  }
  if (ignore_idle_status_ &&
      status.current_operation() > update_engine::Operation::IDLE) {
    ignore_idle_status_ = false;
  }

  time_estimator_.Update(status);

  bool exit_update = false;
  switch (status.current_operation()) {
    case update_engine::Operation::CHECKING_FOR_UPDATE:
      break;
    case update_engine::Operation::UPDATE_AVAILABLE:
      update_info_.progress = kBeforeDownloadProgress;
      update_info_.progress_message =
          l10n_util::GetStringUTF16(IDS_UPDATE_AVAILABLE);
      update_info_.show_estimated_time_left = false;
      update_info_.progress_unavailable = false;
      break;
    case update_engine::Operation::DOWNLOADING:
      update_info_.progress_message =
          l10n_util::GetStringUTF16(IDS_INSTALLING_UPDATE);
      update_info_.progress_unavailable = false;
      update_info_.progress =
          kBeforeDownloadProgress +
          static_cast<int>(status.progress() * kDownloadProgressIncrement);
      update_info_.show_estimated_time_left = time_estimator_.HasDownloadTime();
      update_info_.estimated_time_left_in_secs =
          time_estimator_.GetDownloadTimeLeft().InSeconds();
      break;
    case update_engine::Operation::VERIFYING:
      update_info_.progress = kBeforeVerifyingProgress;
      update_info_.progress_message =
          l10n_util::GetStringUTF16(IDS_UPDATE_VERIFYING);
      update_info_.show_estimated_time_left = false;
      break;
    case update_engine::Operation::FINALIZING:
      update_info_.progress = kBeforeFinalizingProgress;
      update_info_.progress_message =
          l10n_util::GetStringUTF16(IDS_UPDATE_FINALIZING);
      update_info_.show_estimated_time_left = false;
      break;
    case update_engine::Operation::UPDATED_NEED_REBOOT:
      update_info_.progress = kProgressComplete;
      update_info_.show_estimated_time_left = false;
      update_info_.progress_unavailable = false;
      break;
    case update_engine::Operation::NEED_PERMISSION_TO_UPDATE:
      VLOG(1) << "Update requires user permission to proceed.";
      update_info_.state = State::STATE_REQUESTING_USER_PERMISSION;
      update_info_.update_version = status.new_version();
      update_info_.update_size = status.new_size();
      update_info_.requires_permission_for_cellular = true;
      update_info_.progress_unavailable = false;

      DBusThreadManager::Get()->GetUpdateEngineClient()->RemoveObserver(this);
      break;
    case update_engine::Operation::ATTEMPTING_ROLLBACK:
      VLOG(1) << "Attempting rollback";
      break;
    case update_engine::Operation::IDLE:
      // Exit update only if update engine was in non-idle status before.
      // Otherwise, it's possible that the update request has not yet been
      // started.
      if (!ignore_idle_status_)
        exit_update = true;
      break;
    case update_engine::Operation::DISABLED:
    case update_engine::Operation::ERROR:
    case update_engine::Operation::REPORTING_ERROR_EVENT:
      break;
    default:
      NOTREACHED();
  }

  if (time_estimator_.HasTotalTime(status.current_operation())) {
    const auto update_status = time_estimator_.GetUpdateStatus();
    update_info_.total_time_left = update_status.time_left;
    update_info_.better_update_progress = update_status.progress;
    if (!refresh_timer_) {
      refresh_timer_ = std::make_unique<base::RepeatingTimer>(tick_clock_);
      refresh_timer_->Start(FROM_HERE, kUpdateTime, this,
                            &VersionUpdater::RefreshTimeLeftEstimation);
    }
  } else {
    if (refresh_timer_) {
      refresh_timer_->Stop();
      refresh_timer_.reset();
    }
  }

  delegate_->UpdateInfoChanged(update_info_);
  if (exit_update)
    StartExitUpdate(Result::UPDATE_NOT_REQUIRED);
}

void VersionUpdater::RefreshTimeLeftEstimation() {
  const auto update_status = time_estimator_.GetUpdateStatus();
  update_info_.total_time_left = update_status.time_left;
  update_info_.better_update_progress = update_status.progress;
  delegate_->UpdateInfoChanged(update_info_);
}

void VersionUpdater::OnPortalDetectionCompleted(
    const NetworkState* network,
    const NetworkPortalDetector::CaptivePortalState& state) {
  VLOG(1) << "VersionUpdater::OnPortalDetectionCompleted(): "
          << "network=" << (network ? network->path() : "") << ", "
          << "state.status=" << state.status << ", "
          << "state.response_code=" << state.response_code;

  // Wait for sane detection results.
  if (network &&
      state.status == NetworkPortalDetector::CAPTIVE_PORTAL_STATUS_UNKNOWN) {
    return;
  }

  // Restart portal detection for the first notification about offline state.
  if ((!network ||
       state.status == NetworkPortalDetector::CAPTIVE_PORTAL_STATUS_OFFLINE) &&
      is_first_detection_notification_) {
    is_first_detection_notification_ = false;
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE, base::BindOnce([]() {
          network_portal_detector::GetInstance()->StartPortalDetection(
              false /* force */);
        }));
    return;
  }
  is_first_detection_notification_ = false;

  NetworkPortalDetector::CaptivePortalStatus status = state.status;
  if (update_info_.state == State::STATE_ERROR) {
    // In the case of online state hide error message and proceed to
    // the update stage. Otherwise, update error message content.
    if (status == NetworkPortalDetector::CAPTIVE_PORTAL_STATUS_ONLINE)
      StartUpdateCheck();
    else
      UpdateErrorMessage(network, status);
  } else if (update_info_.state == State::STATE_FIRST_PORTAL_CHECK) {
    // In the case of online state immediately proceed to the update
    // stage. Otherwise, prepare and show error message.
    if (status == NetworkPortalDetector::CAPTIVE_PORTAL_STATUS_ONLINE) {
      StartUpdateCheck();
    } else {
      UpdateErrorMessage(network, status);

      // StartUpdateCheck, which gets called when the error clears up, will add
      // the update engine observer back.
      DBusThreadManager::Get()->GetUpdateEngineClient()->RemoveObserver(this);

      update_info_.state = State::STATE_ERROR;
      delegate_->UpdateInfoChanged(update_info_);
      if (status == NetworkPortalDetector::CAPTIVE_PORTAL_STATUS_PORTAL)
        delegate_->DelayErrorMessage();
      else
        delegate_->ShowErrorMessage();
    }
  }
}

void VersionUpdater::OnWaitForRebootTimeElapsed() {
  delegate_->OnWaitForRebootTimeElapsed();
}

void VersionUpdater::UpdateErrorMessage(
    const NetworkState* network,
    const NetworkPortalDetector::CaptivePortalStatus status) {
  std::string network_name = std::string();
  NetworkError::ErrorState error_state;
  switch (status) {
    case NetworkPortalDetector::CAPTIVE_PORTAL_STATUS_UNKNOWN:
    case NetworkPortalDetector::CAPTIVE_PORTAL_STATUS_OFFLINE:
      error_state = NetworkError::ERROR_STATE_OFFLINE;
      break;
    case NetworkPortalDetector::CAPTIVE_PORTAL_STATUS_PORTAL:
      DCHECK(network);
      error_state = NetworkError::ERROR_STATE_PORTAL;
      network_name = network->name();
      break;
    case NetworkPortalDetector::CAPTIVE_PORTAL_STATUS_PROXY_AUTH_REQUIRED:
      error_state = NetworkError::ERROR_STATE_PROXY;
      break;
    default:
      NOTREACHED();
      return;
  }
  delegate_->UpdateErrorMessage(status, error_state, network_name);
}

void VersionUpdater::OnSetUpdateOverCellularOneTimePermission(bool success) {
  update_info_.requires_permission_for_cellular = false;
  if (!success) {
    // Reset UI context to show curtain again when the user goes back to the
    // screen.
    update_info_.progress_unavailable = true;
  }
  delegate_->UpdateInfoChanged(update_info_);

  if (success) {
    StartUpdateCheck();
  } else {
    StartExitUpdate(Result::UPDATE_ERROR);
  }
}

void VersionUpdater::OnUpdateCheckStarted(
    UpdateEngineClient::UpdateCheckResult result) {
  VLOG(1) << "Callback from RequestUpdateCheck, result " << result;
  if (result != UpdateEngineClient::UPDATE_RESULT_SUCCESS)
    StartExitUpdate(Result::UPDATE_NOT_REQUIRED);
}

}  // namespace chromeos
