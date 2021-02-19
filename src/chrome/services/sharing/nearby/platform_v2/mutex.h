// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_SERVICES_SHARING_NEARBY_PLATFORM_V2_MUTEX_H_
#define CHROME_SERVICES_SHARING_NEARBY_PLATFORM_V2_MUTEX_H_

#include "base/synchronization/lock.h"
#include "third_party/nearby/src/cpp/platform_v2/api/mutex.h"

namespace location {
namespace nearby {
namespace chrome {

// Concrete Mutex implementation. Non-recursive lock.
class Mutex : public api::Mutex {
 public:
  Mutex();
  ~Mutex() override;

  Mutex(const Mutex&) = delete;
  Mutex& operator=(const Mutex&) = delete;

  // api::Mutex:
  void Lock() override;
  void Unlock() override;

 private:
  friend class ConditionVariable;
  base::Lock lock_;
};

}  // namespace chrome
}  // namespace nearby
}  // namespace location

#endif  // CHROME_SERVICES_SHARING_NEARBY_PLATFORM_V2_MUTEX_H_
