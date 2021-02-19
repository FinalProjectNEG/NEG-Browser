// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ASH_PUBLIC_CPP_VM_CAMERA_MIC_CONSTANTS_H_
#define ASH_PUBLIC_CPP_VM_CAMERA_MIC_CONSTANTS_H_

#include "ash/public/cpp/ash_public_export.h"

namespace ash {

// Notifier Ids used by VM mic/camera notifiations to avoid being counted by
// `NotificationCounterView`.
ASH_PUBLIC_EXPORT extern const char kVmMicNotifierId[];
ASH_PUBLIC_EXPORT extern const char kVmCameraNotifierId[];

}  // namespace ash

#endif  // ASH_PUBLIC_CPP_VM_CAMERA_MIC_CONSTANTS_H_
