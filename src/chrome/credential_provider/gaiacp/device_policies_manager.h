// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_CREDENTIAL_PROVIDER_GAIACP_DEVICE_POLICIES_MANAGER_H_
#define CHROME_CREDENTIAL_PROVIDER_GAIACP_DEVICE_POLICIES_MANAGER_H_

#include "chrome/credential_provider/gaiacp/device_policies.h"

namespace credential_provider {

// Manager used to fetch user policies from GCPW backends.
class DevicePoliciesManager {
 public:
  // Get the user policies manager instance.
  static DevicePoliciesManager* Get();

  // Return true if cloud policies feature is enabled.
  bool CloudPoliciesEnabled() const;

  // Returns the effective policy to follow on the device by combining the
  // policies of all the existing users on the device.
  virtual void GetDevicePolicies(DevicePolicies* device_policies);

  // Make sure GCPW update is set up correctly.
  void EnforceGcpwUpdatePolicy();

 protected:
  // Returns the storage used for the instance pointer.
  static DevicePoliciesManager** GetInstanceStorage();

  DevicePoliciesManager();
  virtual ~DevicePoliciesManager();
};

}  // namespace credential_provider

#endif  // CHROME_CREDENTIAL_PROVIDER_GAIACP_DEVICE_POLICIES_MANAGER_H_
