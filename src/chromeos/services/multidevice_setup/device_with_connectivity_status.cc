// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chromeos/services/multidevice_setup/device_with_connectivity_status.h"

#include "base/base64.h"
#include "base/stl_util.h"

namespace chromeos {

namespace multidevice {

DeviceWithConnectivityStatus::DeviceWithConnectivityStatus(
    RemoteDeviceRef remote_device,
    cryptauthv2::ConnectivityStatus connectivity_status)
    : remote_device(remote_device), connectivity_status(connectivity_status) {}

DeviceWithConnectivityStatus::DeviceWithConnectivityStatus(
    const DeviceWithConnectivityStatus& other) = default;

DeviceWithConnectivityStatus::~DeviceWithConnectivityStatus() = default;

bool DeviceWithConnectivityStatus::operator==(
    const DeviceWithConnectivityStatus& other) const {
  return remote_device == other.remote_device &&
         connectivity_status == other.connectivity_status;
}

}  // namespace multidevice

}  // namespace chromeos
