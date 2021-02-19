// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ASH_FRAME_THROTTLER_MOCK_FRAME_THROTTLING_OBSERVER_H_
#define ASH_FRAME_THROTTLER_MOCK_FRAME_THROTTLING_OBSERVER_H_

#include <vector>

#include "ash/frame_throttler/frame_throttling_controller.h"
#include "base/memory/weak_ptr.h"
#include "testing/gmock/include/gmock/gmock.h"

namespace ash {

class MockFrameThrottlingObserver : public FrameThrottlingController::Observer {
 public:
  MockFrameThrottlingObserver();
  ~MockFrameThrottlingObserver() override;

  MOCK_METHOD(void,
              OnThrottlingStarted,
              (const std::vector<aura::Window*>& windows),
              (override));
  MOCK_METHOD(void, OnThrottlingEnded, (), (override));
};

}  // namespace ash

#endif  // ASH_FRAME_THROTTLER_MOCK_FRAME_THROTTLING_OBSERVER_H_
