// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/services/sharing/nearby/platform_v2/mutex.h"

namespace location {
namespace nearby {
namespace chrome {

Mutex::Mutex() = default;

Mutex::~Mutex() = default;

void Mutex::Lock() EXCLUSIVE_LOCK_FUNCTION() {
  lock_.Acquire();
}

void Mutex::Unlock() UNLOCK_FUNCTION() {
  lock_.Release();
}

}  // namespace chrome
}  // namespace nearby
}  // namespace location
