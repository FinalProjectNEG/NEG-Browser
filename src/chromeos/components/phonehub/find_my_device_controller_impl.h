// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROMEOS_COMPONENTS_PHONEHUB_FIND_MY_DEVICE_CONTROLLER_IMPL_H_
#define CHROMEOS_COMPONENTS_PHONEHUB_FIND_MY_DEVICE_CONTROLLER_IMPL_H_

#include "chromeos/components/phonehub/do_not_disturb_controller.h"
#include "chromeos/components/phonehub/find_my_device_controller.h"

namespace chromeos {
namespace phonehub {

class MessageSender;

// Responsible for sending and receiving updates in regards to the Find My
// Device feature which involves ringing the user's remote phone.
class FindMyDeviceControllerImpl : public FindMyDeviceController,
                                   public DoNotDisturbController::Observer {
 public:
  FindMyDeviceControllerImpl(DoNotDisturbController* do_not_disturb_controller,
                             MessageSender* message_sender);
  ~FindMyDeviceControllerImpl() override;

 private:
  friend class FindMyDeviceControllerImplTest;

  Status ComputeStatus() const;
  void UpdateStatus();

  // FindMyDeviceController:
  void SetIsPhoneRingingInternal(bool is_phone_ringing) override;
  void RequestNewPhoneRingingState(bool ringing) override;
  Status GetPhoneRingingStatus() override;

  // DoNotDisturbController::Observer:
  void OnDndStateChanged() override;

  bool is_phone_ringing_ = false;
  Status phone_ringing_status_ = Status::kRingingOff;

  DoNotDisturbController* do_not_disturb_controller_;
  MessageSender* message_sender_;
};

}  // namespace phonehub
}  // namespace chromeos

#endif  // CHROMEOS_COMPONENTS_PHONEHUB_FIND_MY_DEVICE_CONTROLLER_IMPL_H_
