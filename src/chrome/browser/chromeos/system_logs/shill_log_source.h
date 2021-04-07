// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_CHROMEOS_SYSTEM_LOGS_SHILL_LOG_SOURCE_H_
#define CHROME_BROWSER_CHROMEOS_SYSTEM_LOGS_SHILL_LOG_SOURCE_H_

#include <map>
#include <set>
#include <string>

#include "base/memory/weak_ptr.h"
#include "base/optional.h"
#include "base/values.h"
#include "components/feedback/system_logs/system_logs_source.h"

namespace system_logs {

// Gathers Device and Service properties from Shill for system/feedback logs.
class ShillLogSource : public SystemLogsSource {
 public:
  explicit ShillLogSource(bool scrub);
  ~ShillLogSource() override;
  ShillLogSource(const ShillLogSource&) = delete;
  ShillLogSource& operator=(const ShillLogSource&) = delete;

  // SystemLogsSource
  void Fetch(SysLogsSourceCallback callback) override;

 private:
  void OnGetManagerProperties(base::Optional<base::Value> result);
  void OnGetDevice(const std::string& device_path,
                   base::Optional<base::Value> properties);
  void AddDeviceAndRequestIPConfigs(const std::string& device_path,
                                    const base::Value& properties);
  void OnGetIPConfig(const std::string& device_path,
                     const std::string& ip_config_path,
                     base::Optional<base::Value> properties);
  void AddIPConfig(const std::string& device_path,
                   const std::string& ip_config_path,
                   const base::Value& properties);
  void OnGetService(const std::string& service_path,
                    base::Optional<base::Value> properties);
  // Scrubs |properties| for PII data based on the |object_path|. Also expands
  // UIData from JSON into a dictionary if present.
  base::Value ScrubAndExpandProperties(const std::string& object_path,
                                       const base::Value& properties);
  // Check whether all property requests have completed. If so, invoke
  // |callback_| and clear results.
  void CheckIfDone();

  const bool scrub_;
  SysLogsSourceCallback callback_;
  std::set<std::string> device_paths_;
  std::set<std::string> service_paths_;
  // More than one device may request the same IP configs, so use multiset.
  std::multiset<std::string> ip_config_paths_;
  base::Value devices_{base::Value::Type::DICTIONARY};
  base::Value services_{base::Value::Type::DICTIONARY};
  base::WeakPtrFactory<ShillLogSource> weak_ptr_factory_{this};
};

}  // namespace system_logs

#endif  // CHROME_BROWSER_CHROMEOS_SYSTEM_LOGS_SHILL_LOG_SOURCE_H_
