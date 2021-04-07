// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROMEOS_SERVICES_DEVICE_SYNC_PUBLIC_CPP_GCM_DEVICE_INFO_PROVIDER_H_
#define CHROMEOS_SERVICES_DEVICE_SYNC_PUBLIC_CPP_GCM_DEVICE_INFO_PROVIDER_H_

#include "base/macros.h"
#include "chromeos/services/device_sync/proto/cryptauth_api.pb.h"

namespace chromeos {

namespace device_sync {

// Provides the cryptauth::GcmDeviceInfo object associated with the current
// device. cryptauth::GcmDeviceInfo describes properties of this Chromebook and
// is not expected to change except when the OS version is updated.
class GcmDeviceInfoProvider {
 public:
  GcmDeviceInfoProvider() = default;
  virtual ~GcmDeviceInfoProvider() = default;

  virtual const cryptauth::GcmDeviceInfo& GetGcmDeviceInfo() const = 0;

 private:
  DISALLOW_COPY_AND_ASSIGN(GcmDeviceInfoProvider);
};

}  // namespace device_sync

}  // namespace chromeos

#endif  // CHROMEOS_SERVICES_DEVICE_SYNC_PUBLIC_CPP_GCM_DEVICE_INFO_PROVIDER_H_
