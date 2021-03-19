// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_CHROMEOS_POLICY_ENROLLMENT_REQUISITION_MANAGER_H_
#define CHROME_BROWSER_CHROMEOS_POLICY_ENROLLMENT_REQUISITION_MANAGER_H_

#include <string>

class PrefRegistrySimple;

namespace policy {

// Managed device requisition that is being stored in local state and is used
// during enrollment to specify the intended use of the device.
class EnrollmentRequisitionManager {
 public:
  EnrollmentRequisitionManager() = delete;
  ~EnrollmentRequisitionManager() = delete;
  EnrollmentRequisitionManager(const EnrollmentRequisitionManager&) = delete;
  EnrollmentRequisitionManager* operator=(const EnrollmentRequisitionManager&) =
      delete;

  // Initializes requisition settings at OOBE with values from VPD.
  static void Initialize();

  // Gets/Sets the device requisition.
  static std::string GetDeviceRequisition();
  static void SetDeviceRequisition(const std::string& requisition);
  static bool IsRemoraRequisition();
  static bool IsSharkRequisition();

  // Gets/Sets the sub organization.
  static std::string GetSubOrganization();
  static void SetSubOrganization(const std::string& sub_organization);

  // If set, the device will start the enterprise enrollment OOBE.
  static void SetDeviceEnrollmentAutoStart();

  // Pref registration helper.
  static void RegisterPrefs(PrefRegistrySimple* registry);
};

}  // namespace policy

#endif  // CHROME_BROWSER_CHROMEOS_POLICY_ENROLLMENT_REQUISITION_MANAGER_H_
