// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_RENDERER_HOST_BLOCKED_SCHEME_NAVIGATION_THROTTLE_H_
#define CONTENT_BROWSER_RENDERER_HOST_BLOCKED_SCHEME_NAVIGATION_THROTTLE_H_

#include <memory>

#include "base/macros.h"
#include "content/public/browser/navigation_throttle.h"

namespace content {

// Blocks renderer-initiated top-frame navigations to certain URL schemes
// (currently data: and filesystem:).
class BlockedSchemeNavigationThrottle : public NavigationThrottle {
 public:
  explicit BlockedSchemeNavigationThrottle(NavigationHandle* navigation_handle);
  ~BlockedSchemeNavigationThrottle() override;

  // NavigationThrottle method:
  ThrottleCheckResult WillProcessResponse() override;
  const char* GetNameForLogging() override;

  static std::unique_ptr<NavigationThrottle> CreateThrottleForNavigation(
      NavigationHandle* navigation_handle);

 private:
  DISALLOW_COPY_AND_ASSIGN(BlockedSchemeNavigationThrottle);
};

}  // namespace content

#endif  // CONTENT_BROWSER_RENDERER_HOST_BLOCKED_SCHEME_NAVIGATION_THROTTLE_H_
