// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/chromeos/policy/adb_sideloading_allowance_mode_policy_handler.h"

#include <utility>

#include "base/bind.h"
#include "base/feature_list.h"
#include "base/optional.h"
#include "base/time/time.h"
#include "base/timer/timer.h"
#include "base/values.h"
#include "chrome/browser/browser_process.h"
#include "chrome/browser/browser_process_platform_part.h"
#include "chrome/browser/chromeos/login/screens/reset_screen.h"
#include "chrome/browser/chromeos/policy/browser_policy_connector_chromeos.h"
#include "chrome/common/pref_names.h"
#include "chromeos/constants/chromeos_features.h"
#include "chromeos/dbus/session_manager/session_manager_client.h"
#include "chromeos/settings/cros_settings_names.h"
#include "chromeos/settings/cros_settings_provider.h"
#include "components/policy/proto/chrome_device_policy.pb.h"
#include "components/prefs/pref_registry_simple.h"
#include "components/prefs/pref_service.h"
#include "components/user_manager/user_manager.h"

namespace {

constexpr base::TimeDelta kAdbSideloadingPlannedNotificationWaitTime =
    base::TimeDelta::FromDays(1);

base::Optional<policy::AdbSideloadingAllowanceMode>
GetAdbSideloadingDevicePolicyMode(const chromeos::CrosSettings* cros_settings,
                                  const base::RepeatingClosure callback) {
  auto status = cros_settings->PrepareTrustedValues(callback);

  // If the policy value is still not trusted, return optional null
  if (status != chromeos::CrosSettingsProvider::TRUSTED) {
    return base::nullopt;
  }

  // Get the trusted policy value.
  int sideloading_mode = -1;
  if (!cros_settings->GetInteger(
          chromeos::kDeviceCrostiniArcAdbSideloadingAllowed,
          &sideloading_mode)) {
    // Here we do not return null because we want to handle this case separately
    // and to reset all the prefs for the notifications so that they can be
    // displayed again if the policy changes
    return policy::AdbSideloadingAllowanceMode::kNotSet;
  }

  using Mode =
      enterprise_management::DeviceCrostiniArcAdbSideloadingAllowedProto;

  switch (sideloading_mode) {
    case Mode::DISALLOW:
      return policy::AdbSideloadingAllowanceMode::kDisallow;
    case Mode::DISALLOW_WITH_POWERWASH:
      return policy::AdbSideloadingAllowanceMode::kDisallowWithPowerwash;
    case Mode::ALLOW_FOR_AFFILIATED_USERS:
      return policy::AdbSideloadingAllowanceMode::kAllowForAffiliatedUser;
    default:
      return base::nullopt;
  }
}
}  // namespace

namespace policy {

// static
void AdbSideloadingAllowanceModePolicyHandler::RegisterPrefs(
    PrefRegistrySimple* registry) {
  registry->RegisterBooleanPref(prefs::kForceFactoryReset, false);
  registry->RegisterBooleanPref(
      prefs::kAdbSideloadingDisallowedNotificationShown, false);
  registry->RegisterTimePref(
      prefs::kAdbSideloadingPowerwashPlannedNotificationShownTime,
      base::Time::Min());
  registry->RegisterBooleanPref(
      prefs::kAdbSideloadingPowerwashOnNextRebootNotificationShown, false);
}

AdbSideloadingAllowanceModePolicyHandler::
    AdbSideloadingAllowanceModePolicyHandler(
        chromeos::CrosSettings* cros_settings,
        PrefService* local_state,
        chromeos::AdbSideloadingPolicyChangeNotification*
            adb_sideloading_policy_change_notification)
    : cros_settings_(cros_settings),
      local_state_(local_state),
      adb_sideloading_policy_change_notification_(
          adb_sideloading_policy_change_notification) {
  DCHECK(local_state_);
  policy_subscription_ = cros_settings_->AddSettingsObserver(
      chromeos::kDeviceCrostiniArcAdbSideloadingAllowed,
      base::BindRepeating(
          &AdbSideloadingAllowanceModePolicyHandler::OnPolicyChanged,
          weak_factory_.GetWeakPtr()));

  check_sideloading_status_callback_ = base::BindRepeating(
      &AdbSideloadingAllowanceModePolicyHandler::CheckSideloadingStatus,
      weak_factory_.GetWeakPtr());

  notification_timer_ = std::make_unique<base::OneShotTimer>();
}

AdbSideloadingAllowanceModePolicyHandler::
    ~AdbSideloadingAllowanceModePolicyHandler() = default;

void AdbSideloadingAllowanceModePolicyHandler::
    SetCheckSideloadingStatusCallbackForTesting(
        const CheckSideloadingStatusCallback& callback) {
  check_sideloading_status_callback_ = callback;
}

void AdbSideloadingAllowanceModePolicyHandler::SetNotificationTimerForTesting(
    std::unique_ptr<base::OneShotTimer> timer) {
  notification_timer_ = std::move(timer);
}

void AdbSideloadingAllowanceModePolicyHandler::OnPolicyChanged() {
  base::Optional<policy::AdbSideloadingAllowanceMode> mode =
      GetAdbSideloadingDevicePolicyMode(
          cros_settings_,
          base::BindRepeating(
              &AdbSideloadingAllowanceModePolicyHandler::OnPolicyChanged,
              weak_factory_.GetWeakPtr()));

  if (!mode.has_value()) {
    return;
  }

  switch (*mode) {
    case AdbSideloadingAllowanceMode::kDisallow:
      // Reset the prefs for the powerwash notifications so they can be shown
      // again if the policy changes
      ClearPowerwashNotificationPrefs();
      check_sideloading_status_callback_.Run(
          base::BindOnce(&AdbSideloadingAllowanceModePolicyHandler::
                             MaybeShowDisallowedNotification,
                         weak_factory_.GetWeakPtr()));
      return;
    case AdbSideloadingAllowanceMode::kDisallowWithPowerwash:
      // Reset the pref for the disallowed notification so it can be shown again
      // if the policy changes
      ClearDisallowedNotificationPref();
      check_sideloading_status_callback_.Run(
          base::BindOnce(&AdbSideloadingAllowanceModePolicyHandler::
                             MaybeShowPowerwashNotification,
                         weak_factory_.GetWeakPtr()));
      return;
    case AdbSideloadingAllowanceMode::kNotSet:
    case AdbSideloadingAllowanceMode::kAllowForAffiliatedUser:
      // Reset all the prefs so the notifications can be shown again if the
      // policy changes
      ClearDisallowedNotificationPref();
      ClearPowerwashNotificationPrefs();
      notification_timer_->Stop();
      return;
  }
}

void AdbSideloadingAllowanceModePolicyHandler::CheckSideloadingStatus(
    base::OnceCallback<void(bool)> callback) {
  // If the feature is not enabled, never show a notification
  if (!base::FeatureList::IsEnabled(
          chromeos::features::kArcManagedAdbSideloadingSupport)) {
    std::move(callback).Run(false);
    return;
  }

  using ResponseCode = chromeos::SessionManagerClient::AdbSideloadResponseCode;

  auto* client = chromeos::SessionManagerClient::Get();
  client->QueryAdbSideload(base::BindOnce(
      [](base::OnceCallback<void(bool)> callback, ResponseCode response_code,
         bool enabled) {
        switch (response_code) {
          case ResponseCode::SUCCESS:
            // Everything is fine, so pass the |enabled| value to |callback|.
            break;
          case ResponseCode::FAILED:
            // Status could not be established so return false so that the
            // notifications would not be shown.
            enabled = false;
            break;
          case ResponseCode::NEED_POWERWASH:
            // This can only happen on devices initialized before M74, i.e. not
            // powerwashed since then. Do not show the notifications there.
            enabled = false;
            break;
        }
        std::move(callback).Run(enabled);
      },
      std::move(callback)));
}

void AdbSideloadingAllowanceModePolicyHandler::
    ShowAdbSideloadingPolicyChangeNotificationIfNeeded() {
  OnPolicyChanged();
}

bool AdbSideloadingAllowanceModePolicyHandler::
    WasDisallowedNotificationShown() {
  return local_state_->GetBoolean(
      prefs::kAdbSideloadingDisallowedNotificationShown);
}

bool AdbSideloadingAllowanceModePolicyHandler::
    WasPowerwashOnNextRebootNotificationShown() {
  return local_state_->GetBoolean(
      prefs::kAdbSideloadingPowerwashOnNextRebootNotificationShown);
}

void AdbSideloadingAllowanceModePolicyHandler::MaybeShowDisallowedNotification(
    bool is_sideloading_enabled) {
  if (!is_sideloading_enabled)
    return;

  if (WasDisallowedNotificationShown())
    return;

  local_state_->SetBoolean(prefs::kAdbSideloadingDisallowedNotificationShown,
                           true);
  adb_sideloading_policy_change_notification_->Show(
      NotificationType::kSideloadingDisallowed);
}

void AdbSideloadingAllowanceModePolicyHandler::MaybeShowPowerwashNotification(
    bool is_sideloading_enabled) {
  if (!is_sideloading_enabled)
    return;

  base::Time notification_shown_time = local_state_->GetTime(
      prefs::kAdbSideloadingPowerwashPlannedNotificationShownTime);

  // If the time has not been set yet, set it and show the planned notification
  if (notification_shown_time.is_min()) {
    notification_shown_time = base::Time::Now();
    local_state_->SetTime(
        prefs::kAdbSideloadingPowerwashPlannedNotificationShownTime,
        notification_shown_time);
    adb_sideloading_policy_change_notification_->Show(
        NotificationType::kPowerwashPlanned);
  }

  // Show update on next reboot notification after at least
  // |kAdbSideloadingPlannedNotificationWaitTime|.
  base::Time show_reboot_notification_time =
      notification_shown_time + kAdbSideloadingPlannedNotificationWaitTime;

  // If this time has already been reached stop the timer and show the
  // notification immediately.
  if (show_reboot_notification_time <= base::Time::Now()) {
    notification_timer_->Stop();
    MaybeShowPowerwashUponRebootNotification();
    return;
  }

  // Otherwise set a timer that will display the |kPowerwashOnNextReboot|
  // notification no earlier than |kAdbSideloadingPlannedNotificationWaitTime|
  // after showing the |kPowerwashPlanned| notification.
  if (notification_timer_->IsRunning())
    return;
  notification_timer_->Start(
      FROM_HERE, show_reboot_notification_time - base::Time::Now(), this,
      &AdbSideloadingAllowanceModePolicyHandler::
          MaybeShowPowerwashUponRebootNotification);
}

void AdbSideloadingAllowanceModePolicyHandler::
    MaybeShowPowerwashUponRebootNotification() {
  if (WasPowerwashOnNextRebootNotificationShown())
    return;

  local_state_->SetBoolean(
      prefs::kAdbSideloadingPowerwashOnNextRebootNotificationShown, true);

  // Set this right away to ensure the user is forced to powerwash on next
  // start even if they ignore the notification and do not click the button
  local_state_->SetBoolean(prefs::kForceFactoryReset, true);
  local_state_->CommitPendingWrite();

  adb_sideloading_policy_change_notification_->Show(
      NotificationType::kPowerwashOnNextReboot);
}

void AdbSideloadingAllowanceModePolicyHandler::
    ClearDisallowedNotificationPref() {
  local_state_->ClearPref(prefs::kAdbSideloadingDisallowedNotificationShown);
}

void AdbSideloadingAllowanceModePolicyHandler::
    ClearPowerwashNotificationPrefs() {
  local_state_->ClearPref(
      prefs::kAdbSideloadingPowerwashPlannedNotificationShownTime);
  local_state_->ClearPref(
      prefs::kAdbSideloadingPowerwashOnNextRebootNotificationShown);
}

}  // namespace policy
