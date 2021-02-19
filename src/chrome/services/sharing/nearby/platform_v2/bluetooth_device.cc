// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/services/sharing/nearby/platform_v2/bluetooth_device.h"

namespace location {
namespace nearby {
namespace chrome {

BluetoothDevice::BluetoothDevice(bluetooth::mojom::DeviceInfoPtr device_info)
    : device_info_(std::move(device_info)) {}

BluetoothDevice::~BluetoothDevice() = default;

std::string BluetoothDevice::GetName() const {
  return device_info_->name_for_display;
}

std::string BluetoothDevice::GetMacAddress() const {
  return device_info_->address;
}

void BluetoothDevice::UpdateDeviceInfo(
    bluetooth::mojom::DeviceInfoPtr device_info) {
  DCHECK_EQ(device_info_->address, device_info->address);
  device_info_ = std::move(device_info);
}

}  // namespace chrome
}  // namespace nearby
}  // namespace location
