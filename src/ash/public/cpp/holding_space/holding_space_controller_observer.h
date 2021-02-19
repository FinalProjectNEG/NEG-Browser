// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ASH_PUBLIC_CPP_HOLDING_SPACE_HOLDING_SPACE_CONTROLLER_OBSERVER_H_
#define ASH_PUBLIC_CPP_HOLDING_SPACE_HOLDING_SPACE_CONTROLLER_OBSERVER_H_

#include "ash/public/cpp/ash_public_export.h"
#include "base/observer_list_types.h"

namespace ash {

class HoldingSpaceModel;

class ASH_PUBLIC_EXPORT HoldingSpaceControllerObserver
    : public base::CheckedObserver {
 public:
  // Called when a model gets attached to the HoldingSpaceController.
  virtual void OnHoldingSpaceModelAttached(HoldingSpaceModel* model) = 0;

  // Called when a model gets detached from the HoldingSpaceController.
  virtual void OnHoldingSpaceModelDetached(HoldingSpaceModel* model) = 0;
};

}  // namespace ash

#endif  // ASH_PUBLIC_CPP_HOLDING_SPACE_HOLDING_SPACE_CONTROLLER_OBSERVER_H_
