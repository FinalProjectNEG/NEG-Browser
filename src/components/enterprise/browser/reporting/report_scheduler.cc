// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/enterprise/browser/reporting/report_scheduler.h"

#include <string>
#include <utility>
#include <vector>

#include "base/metrics/histogram_functions.h"
#include "base/syslog_logging.h"
#include "base/task/post_task.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "components/enterprise/browser/controller/browser_dm_token_storage.h"
#include "components/enterprise/browser/reporting/common_pref_names.h"
#include "components/enterprise/browser/reporting/reporting_delegate_factory.h"
#include "components/policy/core/common/cloud/cloud_policy_client.h"
#include "components/policy/core/common/cloud/device_management_service.h"
#include "components/prefs/pref_service.h"

namespace em = enterprise_management;

namespace enterprise_reporting {

namespace {

constexpr base::TimeDelta kDefaultUploadInterval =
    base::TimeDelta::FromHours(24);  // Default upload interval is 24 hours.
const int kMaximumRetry = 10;  // Retry 10 times takes about 15 to 19 hours.

}  // namespace

ReportScheduler::Delegate::Delegate() = default;
ReportScheduler::Delegate::~Delegate() = default;

void ReportScheduler::Delegate::SetReportTriggerCallback(
    ReportScheduler::ReportTriggerCallback callback) {
  DCHECK(trigger_report_callback_.is_null());
  trigger_report_callback_ = std::move(callback);
}

ReportScheduler::ReportScheduler(
    policy::CloudPolicyClient* client,
    std::unique_ptr<ReportGenerator> report_generator,
    ReportingDelegateFactory* delegate_factory)
    : ReportScheduler(std::move(client),
                      std::move(report_generator),
                      delegate_factory->GetReportSchedulerDelegate()) {}

ReportScheduler::ReportScheduler(
    policy::CloudPolicyClient* client,
    std::unique_ptr<ReportGenerator> report_generator,
    std::unique_ptr<ReportScheduler::Delegate> delegate)
    : delegate_(std::move(delegate)),
      cloud_policy_client_(std::move(client)),
      report_generator_(std::move(report_generator)) {
  delegate_->SetReportTriggerCallback(
      base::BindRepeating(&ReportScheduler::GenerateAndUploadReport,
                          weak_ptr_factory_.GetWeakPtr()));
  RegisterPrefObserver();
}

ReportScheduler::~ReportScheduler() = default;

bool ReportScheduler::IsReportingEnabled() const {
  return delegate_->GetLocalState()->GetBoolean(kCloudReportingEnabled);
}

bool ReportScheduler::IsNextReportScheduledForTesting() const {
  return request_timer_.IsRunning();
}

void ReportScheduler::SetReportUploaderForTesting(
    std::unique_ptr<ReportUploader> uploader) {
  report_uploader_ = std::move(uploader);
}

void ReportScheduler::OnDMTokenUpdated() {
  OnReportEnabledPrefChanged();
}

void ReportScheduler::RegisterPrefObserver() {
  pref_change_registrar_.Init(delegate_->GetLocalState());
  pref_change_registrar_.Add(
      kCloudReportingEnabled,
      base::BindRepeating(&ReportScheduler::OnReportEnabledPrefChanged,
                          base::Unretained(this)));
  // Trigger first pref check during launch process.
  OnReportEnabledPrefChanged();
}

void ReportScheduler::OnReportEnabledPrefChanged() {
  if (!IsReportingEnabled()) {
    Stop();
    return;
  }

  // For Chrome OS, it needn't register the cloud policy client here. The
  // |dm_token| and |client_id| should have already existed after the client is
  // initialized, and will keep valid during whole life-cycle.
#if !defined(OS_CHROMEOS)
  if (!SetupBrowserPolicyClientRegistration()) {
    Stop();
    return;
  }
#endif

  // Start the periodic report timer.
  const base::Time last_upload_timestamp =
      delegate_->GetLocalState()->GetTime(kLastUploadTimestamp);
  Start(last_upload_timestamp);

  delegate_->StartWatchingUpdatesIfNeeded(last_upload_timestamp,
                                          kDefaultUploadInterval);
}

void ReportScheduler::Stop() {
  request_timer_.Stop();
  delegate_->StopWatchingUpdates();
}

bool ReportScheduler::SetupBrowserPolicyClientRegistration() {
  if (cloud_policy_client_->is_registered())
    return true;

  policy::DMToken browser_dm_token =
      policy::BrowserDMTokenStorage::Get()->RetrieveDMToken();
  std::string client_id =
      policy::BrowserDMTokenStorage::Get()->RetrieveClientId();

  if (!browser_dm_token.is_valid() || client_id.empty()) {
    VLOG(1)
        << "Enterprise reporting is disabled because device is not enrolled.";
    return false;
  }

  cloud_policy_client_->SetupRegistration(browser_dm_token.value(), client_id,
                                          std::vector<std::string>());
  return true;
}

void ReportScheduler::Start(base::Time last_upload_time) {
  // The next report is triggered 24h after the previous was uploaded.
  const base::Time next_upload_time = last_upload_time + kDefaultUploadInterval;
  if (VLOG_IS_ON(1)) {
    base::TimeDelta first_request_delay = next_upload_time - base::Time::Now();
    VLOG(1) << "Schedule the first report in about "
            << first_request_delay.InHours() << " hour(s) and "
            << first_request_delay.InMinutes() % 60 << " minute(s).";
  }
  request_timer_.Start(FROM_HERE, next_upload_time,
                       base::BindOnce(&ReportScheduler::GenerateAndUploadReport,
                                      base::Unretained(this), kTriggerTimer));
}

void ReportScheduler::GenerateAndUploadReport(ReportTrigger trigger) {
  if (active_trigger_ != kTriggerNone) {
    // A report is already being generated. Remember this trigger to be handled
    // once the current report completes.
    pending_triggers_ |= trigger;
    return;
  }

  active_trigger_ = trigger;
  bool with_profiles = true;
  switch (trigger) {
    case kTriggerNone:
      NOTREACHED();
      FALLTHROUGH;
    case kTriggerTimer:
      VLOG(1) << "Generating enterprise report.";
      break;
    case kTriggerUpdate:
      VLOG(1) << "Generating basic enterprise report upon update.";
      with_profiles = false;
      break;
    case kTriggerNewVersion:
      VLOG(1) << "Generating basic enterprise report upon new version.";
      with_profiles = false;
      break;
  }

  report_generator_->Generate(
      with_profiles, base::BindOnce(&ReportScheduler::OnReportGenerated,
                                    base::Unretained(this)));
}

void ReportScheduler::OnReportGenerated(
    ReportGenerator::ReportRequests requests) {
  DCHECK_NE(active_trigger_, kTriggerNone);
  if (requests.empty()) {
    SYSLOG(ERROR)
        << "No cloud report can be generated. Likely the report is too large.";
    // Do not restart the periodic report timer, as it's likely that subsequent
    // attempts to generate full reports would also fail.
    active_trigger_ = kTriggerNone;
    RunPendingTriggers();
    return;
  }
  VLOG(1) << "Uploading enterprise report.";
  if (!report_uploader_) {
    report_uploader_ =
        std::make_unique<ReportUploader>(cloud_policy_client_, kMaximumRetry);
  }
  RecordUploadTrigger(active_trigger_);
  report_uploader_->SetRequestAndUpload(
      std::move(requests), base::BindOnce(&ReportScheduler::OnReportUploaded,
                                          base::Unretained(this)));
}

void ReportScheduler::OnReportUploaded(ReportUploader::ReportStatus status) {
  DCHECK_NE(active_trigger_, kTriggerNone);
  VLOG(1) << "The enterprise report upload result " << status << ".";
  switch (status) {
    case ReportUploader::kSuccess:
      // Schedule the next report for success. Reset uploader to reset failure
      // count.
      report_uploader_.reset();
      delegate_->SaveLastUploadVersion();
      FALLTHROUGH;
    case ReportUploader::kTransientError:
      // Stop retrying and schedule the next report to avoid stale report.
      // Failure count is not reset so retry delay remains.
      if (active_trigger_ == kTriggerTimer) {
        const base::Time now = base::Time::Now();
        delegate_->GetLocalState()->SetTime(kLastUploadTimestamp, now);
        if (IsReportingEnabled())
          Start(now);
      }
      break;
    case ReportUploader::kPersistentError:
      // No future upload until Chrome relaunch or pref change event.
      break;
  }

  active_trigger_ = kTriggerNone;
  RunPendingTriggers();
}

void ReportScheduler::RunPendingTriggers() {
  DCHECK_EQ(active_trigger_, kTriggerNone);
  if (!pending_triggers_)
    return;

  // Timer-triggered reports are a superset of those triggered by an update or a
  // new version, so favor them and consider that they serve all purposes.
  uint32_t pending_triggers = std::exchange(pending_triggers_, 0);
  ReportTrigger trigger = kTriggerTimer;
  if ((pending_triggers & kTriggerTimer) == 0) {
    trigger = (pending_triggers & kTriggerUpdate) != 0 ? kTriggerUpdate
                                                       : kTriggerNewVersion;
  }
  GenerateAndUploadReport(trigger);
}

// static
void ReportScheduler::RecordUploadTrigger(ReportTrigger trigger) {
  // These values are persisted to logs. Entries should not be renumbered and
  // numeric values should never be reused.
  enum class Sample {
    kNone = 0,
    kTimer = 1,
    kUpdate = 2,
    kNewVersion = 3,
    kMaxValue = kNewVersion
  } sample = Sample::kNone;
  switch (trigger) {
    case kTriggerNone:
      break;
    case kTriggerTimer:
      sample = Sample::kTimer;
      break;
    case kTriggerUpdate:
      sample = Sample::kUpdate;
      break;
    case kTriggerNewVersion:
      sample = Sample::kNewVersion;
      break;
  }
  base::UmaHistogramEnumeration("Enterprise.CloudReportingUploadTrigger",
                                sample);
}

}  // namespace enterprise_reporting
