// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/enterprise/browser/reporting/profile_report_generator.h"

#include <utility>

#include "base/files/file_path.h"
#include "components/enterprise/browser/reporting/policy_info.h"
#include "components/enterprise/browser/reporting/reporting_delegate_factory.h"
#include "components/policy/core/browser/policy_conversions.h"

namespace em = enterprise_management;

namespace enterprise_reporting {

ProfileReportGenerator::ProfileReportGenerator(
    ReportingDelegateFactory* delegate_factory)
    : delegate_(delegate_factory->GetProfileReportGeneratorDelegate()) {}

ProfileReportGenerator::~ProfileReportGenerator() = default;

void ProfileReportGenerator::set_extensions_enabled(bool enabled) {
  extensions_enabled_ = enabled;
}

void ProfileReportGenerator::set_policies_enabled(bool enabled) {
  policies_enabled_ = enabled;
}

std::unique_ptr<em::ChromeUserProfileInfo>
ProfileReportGenerator::MaybeGenerate(const base::FilePath& path,
                                      const std::string& name) {
  if (!delegate_->Init(path)) {
    return nullptr;
  }

  report_ = std::make_unique<em::ChromeUserProfileInfo>();
  report_->set_id(path.AsUTF8Unsafe());
  report_->set_name(name);
  report_->set_is_full_report(true);

  delegate_->GetSigninUserInfo(report_.get());
  if (extensions_enabled_) {
    delegate_->GetExtensionInfo(report_.get());
  }
  delegate_->GetExtensionRequest(report_.get());

  if (policies_enabled_) {
    // TODO(crbug.com/983151): Upload policy error as their IDs.
    auto client = delegate_->MakePolicyConversionsClient();
    policies_ = policy::DictionaryPolicyConversions(std::move(client))
                    .EnableConvertTypes(false)
                    .EnablePrettyPrint(false)
                    .ToValue();
    GetChromePolicyInfo();
    GetExtensionPolicyInfo();
    GetPolicyFetchTimestampInfo();
  }

  return std::move(report_);
}

void ProfileReportGenerator::GetChromePolicyInfo() {
  AppendChromePolicyInfoIntoProfileReport(policies_, report_.get());
}

void ProfileReportGenerator::GetExtensionPolicyInfo() {
  AppendExtensionPolicyInfoIntoProfileReport(policies_, report_.get());
}

void ProfileReportGenerator::GetPolicyFetchTimestampInfo() {
#if !defined(OS_CHROMEOS)
  AppendMachineLevelUserCloudPolicyFetchTimestamp(
      report_.get(), delegate_->GetCloudPolicyManager());
#endif  // !defined(OS_CHROMEOS)
}

}  // namespace enterprise_reporting
