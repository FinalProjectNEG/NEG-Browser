// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/services/sharing/nearby/platform_v2/condition_variable.h"

#include "base/time/time.h"
#include "chrome/services/sharing/nearby/platform_v2/mutex.h"

namespace location {
namespace nearby {
namespace chrome {

ConditionVariable::ConditionVariable(Mutex* mutex)
    : mutex_(mutex), condition_variable_(&mutex_->lock_) {}

ConditionVariable::~ConditionVariable() = default;

Exception ConditionVariable::Wait() {
  condition_variable_.Wait();
  return {Exception::kSuccess};
}

Exception ConditionVariable::Wait(absl::Duration timeout) {
  condition_variable_.TimedWait(
      base::TimeDelta::FromMicroseconds(absl::ToInt64Microseconds(timeout)));
  return {Exception::kSuccess};
}

void ConditionVariable::Notify() {
  condition_variable_.Broadcast();
}

}  // namespace chrome
}  // namespace nearby
}  // namespace location
