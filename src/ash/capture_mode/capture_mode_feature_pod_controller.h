// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ASH_CAPTURE_MODE_CAPTURE_MODE_FEATURE_POD_CONTROLLER_H_
#define ASH_CAPTURE_MODE_CAPTURE_MODE_FEATURE_POD_CONTROLLER_H_

#include "ash/system/unified/feature_pod_controller_base.h"
#include "base/macros.h"

namespace ash {

// Controller of a feature pod button that toggles night light mode.
class CaptureModeFeaturePodController : public FeaturePodControllerBase {
 public:
  CaptureModeFeaturePodController();
  CaptureModeFeaturePodController(const CaptureModeFeaturePodController&) =
      delete;
  CaptureModeFeaturePodController& operator=(
      const CaptureModeFeaturePodController&) = delete;
  ~CaptureModeFeaturePodController() override;

  // FeaturePodControllerBase:
  FeaturePodButton* CreateButton() override;
  void OnIconPressed() override;
  SystemTrayItemUmaType GetUmaType() const override;

 private:
  FeaturePodButton* button_ = nullptr;
};

}  // namespace ash

#endif  // ASH_CAPTURE_MODE_CAPTURE_MODE_FEATURE_POD_CONTROLLER_H_
