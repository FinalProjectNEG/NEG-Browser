// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ASH_PUBLIC_CPP_OVERVIEW_TEST_API_H_
#define ASH_PUBLIC_CPP_OVERVIEW_TEST_API_H_

#include <cstdint>

#include "ash/ash_export.h"
#include "base/callback_forward.h"
#include "base/containers/flat_map.h"
#include "base/macros.h"
#include "base/optional.h"
#include "ui/gfx/geometry/rect.h"

namespace aura {
class Window;
}

namespace ash {

enum class OverviewAnimationState : int32_t {
  kEnterAnimationComplete,
  kExitAnimationComplete,
};

struct OverviewItemInfo {
  // A window represented by an overview item.
  aura::Window* window = nullptr;

  // Screen bounds of an overview item.
  gfx::Rect bounds_in_screen;

  // Whether an overview item is being dragged.
  bool is_dragged = false;
};

// Overview item info keyed by app windows.
using OverviewInfo = base::flat_map<aura::Window*, OverviewItemInfo>;

// Provides access to the limited functions of OverviewController for autotest
// private API.
class ASH_EXPORT OverviewTestApi {
 public:
  OverviewTestApi();
  ~OverviewTestApi();

  using DoneCallback = base::OnceCallback<void(bool animation_succeeded)>;

  // Set the overview mode state to |start|. |done_callback| will be invoked
  // synchronously if the animation is already complete, and asynchronously if
  // the overview state does not match |start|.
  void SetOverviewMode(bool start, DoneCallback done_callback);

  // Runs the callback when overview is finished animating to |expected_state|.
  // Passes true synchronously through |callback| if |expected_state| was
  // already set. Otherwise |callback| is passed whether the animation succeeded
  // asynchronously when the animation completes.
  void WaitForOverviewState(OverviewAnimationState expected_state,
                            DoneCallback callback);

  // Returns overview info for the current overview items if overview is
  // started. Otherwise, returns base::nullopt;
  base::Optional<OverviewInfo> GetOverviewInfo() const;

 private:
  DISALLOW_COPY_AND_ASSIGN(OverviewTestApi);
};

}  // namespace ash

#endif  // ASH_PUBLIC_CPP_OVERVIEW_TEST_API_H_
