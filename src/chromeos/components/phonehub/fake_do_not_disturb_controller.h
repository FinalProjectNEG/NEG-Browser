// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROMEOS_COMPONENTS_PHONEHUB_FAKE_DO_NOT_DISTURB_CONTROLLER_H_
#define CHROMEOS_COMPONENTS_PHONEHUB_FAKE_DO_NOT_DISTURB_CONTROLLER_H_

#include "chromeos/components/phonehub/do_not_disturb_controller.h"

namespace chromeos {
namespace phonehub {

class FakeDoNotDisturbController : public DoNotDisturbController {
 public:
  FakeDoNotDisturbController();
  ~FakeDoNotDisturbController() override;

  // DoNotDisturbController:
  bool IsDndEnabled() const override;
  void SetDoNotDisturbStateInternal(bool is_dnd_enabled) override;
  void RequestNewDoNotDisturbState(bool enabled) override;

  void SetShouldRequestFail(bool should_request_fail);

 private:
  bool is_dnd_enabled_ = false;

  // Indicates if the connection to the phone is working correctly. If it is
  // true, there is a problem and the phone cannot change its state.
  bool should_request_fail_ = false;
};

}  // namespace phonehub
}  // namespace chromeos

#endif  // CHROMEOS_COMPONENTS_PHONEHUB_FAKE_DO_NOT_DISTURB_CONTROLLER_H_
