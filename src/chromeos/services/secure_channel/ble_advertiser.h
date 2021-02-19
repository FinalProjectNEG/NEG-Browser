// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROMEOS_SERVICES_SECURE_CHANNEL_BLE_ADVERTISER_H_
#define CHROMEOS_SERVICES_SECURE_CHANNEL_BLE_ADVERTISER_H_

#include "base/macros.h"
#include "chromeos/services/secure_channel/device_id_pair.h"
#include "chromeos/services/secure_channel/public/cpp/shared/connection_priority.h"

namespace chromeos {

namespace secure_channel {

// Registers BLE advertisements targeted to remote devices.
class BleAdvertiser {
 public:
  class Delegate {
   public:
    virtual ~Delegate() = default;

    // If |replaced_by_higher_priority_advertisement| is true, the timeslot
    // ended due to a higher-priority request taking |device_id_pair|'s spot
    // rather than due to a timeout.
    virtual void OnAdvertisingSlotEnded(
        const DeviceIdPair& device_id_pair,
        bool replaced_by_higher_priority_advertisement) = 0;

    // Invoked when there is a failure to generate an advertisement for
    // |device_id_pair|.
    virtual void OnFailureToGenerateAdvertisement(
        const DeviceIdPair& device_id_pair) = 0;
  };

  virtual ~BleAdvertiser();

  // Adds a request for the given DeviceIdPair to advertise at the given
  // priority.
  //
  // Calling AddAdvertisementRequest() does not guarantee that this Chromebook
  // will immediately begin advertising to the remote device; because BLE
  // advertisements are a shared system resource, requests may be queued. If no
  // advertisement can be generated,
  // Delegate::OnFailureToGenerateAdvertisement() will be invoked.
  virtual void AddAdvertisementRequest(
      const DeviceIdPair& request,
      ConnectionPriority connection_priority) = 0;

  // Updates the priority for a current advertisement.
  virtual void UpdateAdvertisementRequestPriority(
      const DeviceIdPair& request,
      ConnectionPriority connection_priority) = 0;

  // Removes the request for the given DeviceIdPair.
  virtual void RemoveAdvertisementRequest(const DeviceIdPair& request) = 0;

 protected:
  explicit BleAdvertiser(Delegate* delegate);

  void NotifyAdvertisingSlotEnded(
      const DeviceIdPair& device_id_pair,
      bool replaced_by_higher_priority_advertisement);

  void NotifyFailureToGenerateAdvertisement(const DeviceIdPair& device_id_pair);

 private:
  Delegate* delegate_;

  DISALLOW_COPY_AND_ASSIGN(BleAdvertiser);
};

}  // namespace secure_channel

}  // namespace chromeos

#endif  // CHROMEOS_SERVICES_SECURE_CHANNEL_BLE_ADVERTISER_H_
