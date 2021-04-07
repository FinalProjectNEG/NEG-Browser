// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_SERVICES_SHARING_NEARBY_PLATFORM_V2_COUNT_DOWN_LATCH_H_
#define CHROME_SERVICES_SHARING_NEARBY_PLATFORM_V2_COUNT_DOWN_LATCH_H_

#include "base/atomic_ref_count.h"
#include "base/synchronization/waitable_event.h"
#include "third_party/abseil-cpp/absl/time/time.h"
#include "third_party/nearby/src/cpp/platform_v2/api/count_down_latch.h"

namespace location {
namespace nearby {
namespace chrome {

// Concrete CountDownLatch implementation.
class CountDownLatch : public api::CountDownLatch {
 public:
  explicit CountDownLatch(int32_t count);
  ~CountDownLatch() override;

  CountDownLatch(const CountDownLatch&) = delete;
  CountDownLatch& operator=(const CountDownLatch&) = delete;

  // api::CountDownLatch:
  Exception Await() override;
  ExceptionOr<bool> Await(absl::Duration timeout) override;
  void CountDown() override;

 private:
  base::AtomicRefCount count_;
  base::WaitableEvent count_waitable_event_;
};

}  // namespace chrome
}  // namespace nearby
}  // namespace location

#endif  // CHROME_SERVICES_SHARING_NEARBY_PLATFORM_V2_COUNT_DOWN_LATCH_H_
