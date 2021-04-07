// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/enterprise/browser/reporting/report_generator.h"

#include <utility>

#include "base/bind.h"
#include "base/strings/utf_string_conversions.h"
#include "build/build_config.h"
#include "components/enterprise/browser/reporting/browser_report_generator.h"
#include "components/enterprise/browser/reporting/reporting_delegate_factory.h"
#include "components/policy/core/common/cloud/cloud_policy_util.h"

#if defined(OS_WIN)
#include "base/win/wmi.h"
#endif

namespace em = enterprise_management;

namespace enterprise_reporting {

ReportGenerator::ReportGenerator(ReportingDelegateFactory* delegate_factory)
    : delegate_(delegate_factory->GetReportGeneratorDelegate()),
      report_request_queue_generator_(delegate_factory),
      browser_report_generator_(delegate_factory) {}

ReportGenerator::~ReportGenerator() = default;

void ReportGenerator::Generate(bool with_profiles, ReportCallback callback) {
  CreateBasicRequest(std::make_unique<ReportRequest>(), with_profiles,
                     std::move(callback));
}

void ReportGenerator::SetMaximumReportSizeForTesting(size_t size) {
  report_request_queue_generator_.SetMaximumReportSizeForTesting(size);
}

void ReportGenerator::CreateBasicRequest(
    std::unique_ptr<ReportRequest> basic_request,
    bool with_profiles,
    ReportCallback callback) {
#if defined(OS_CHROMEOS)
  delegate_->SetAndroidAppInfos(basic_request.get());
#else
  basic_request->set_computer_name(this->GetMachineName());
  basic_request->set_os_user_name(GetOSUserName());
  basic_request->set_serial_number(GetSerialNumber());
  basic_request->set_allocated_os_report(GetOSReport().release());
  basic_request->set_allocated_browser_device_identifier(
      policy::GetBrowserDeviceIdentifier().release());
#endif

  browser_report_generator_.Generate(base::BindOnce(
      &ReportGenerator::OnBrowserReportReady, weak_ptr_factory_.GetWeakPtr(),
      with_profiles, std::move(callback), std::move(basic_request)));
}

std::unique_ptr<em::OSReport> ReportGenerator::GetOSReport() {
  auto report = std::make_unique<em::OSReport>();
  report->set_name(policy::GetOSPlatform());
  report->set_arch(policy::GetOSArchitecture());
  report->set_version(policy::GetOSVersion());
  return report;
}

std::string ReportGenerator::GetMachineName() {
  return policy::GetMachineName();
}

std::string ReportGenerator::GetOSUserName() {
  return policy::GetOSUsername();
}

std::string ReportGenerator::GetSerialNumber() {
#if defined(OS_WIN)
  return base::UTF16ToUTF8(
      base::win::WmiComputerSystemInfo::Get().serial_number());
#else
  return std::string();
#endif
}

void ReportGenerator::OnBrowserReportReady(
    bool with_profiles,
    ReportCallback callback,
    std::unique_ptr<ReportRequest> basic_request,
    std::unique_ptr<em::BrowserReport> browser_report) {
  basic_request->set_allocated_browser_report(browser_report.release());

  if (with_profiles) {
    // Generate a queue of requests containing detailed profile information.
    std::move(callback).Run(
        report_request_queue_generator_.Generate(*basic_request));
    return;
  }

  // Return a queue containing only the basic request and browser report without
  // detailed profile information.
  ReportRequests requests;
  requests.push(std::move(basic_request));
  std::move(callback).Run(std::move(requests));
}

}  // namespace enterprise_reporting
