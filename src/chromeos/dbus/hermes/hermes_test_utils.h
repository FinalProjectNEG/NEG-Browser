// Copyright (c) 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROMEOS_DBUS_HERMES_HERMES_TEST_UTILS_H_
#define CHROMEOS_DBUS_HERMES_HERMES_TEST_UTILS_H_

#include "testing/gmock/include/gmock/gmock-matchers.h"

namespace chromeos {

enum class HermesResponseStatus;

namespace hermes_test_utils {

// Matches dbus::MethodCall with given method name.
MATCHER_P(MatchMethodName, method_name, "") {
  if (arg->GetMember() != method_name) {
    *result_listener << "has method_name=" << arg->GetMember();
    return false;
  }
  return true;
}

// Copies |status| to |dest_status|. Useful as test callback to capture
// results for methods that return only a status
void CopyHermesStatus(HermesResponseStatus* dest_status,
                      HermesResponseStatus status);

}  // namespace hermes_test_utils
}  // namespace chromeos

#endif  // CHROMEOS_DBUS_HERMES_HERMES_TEST_UTILS_H_
