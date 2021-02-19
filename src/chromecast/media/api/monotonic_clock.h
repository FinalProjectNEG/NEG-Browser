// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROMECAST_MEDIA_API_MONOTONIC_CLOCK_H_
#define CHROMECAST_MEDIA_API_MONOTONIC_CLOCK_H_

#include <stdint.h>

namespace chromecast {
namespace media {

// Interface that provides the monotonic time.
class MonotonicClock {
 public:
  virtual ~MonotonicClock() = default;
  // Returns the monotonic time in microseconds.
  virtual int64_t Now() const = 0;
};

}  // namespace media
}  // namespace chromecast

#endif  // CHROMECAST_MEDIA_API_MONOTONIC_CLOCK_H_
