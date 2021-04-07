// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/ash/screenshot_area.h"

// static
ScreenshotArea ScreenshotArea::CreateForAllRootWindows() {
  return ScreenshotArea(ScreenshotType::kAllRootWindows, nullptr,
                        base::nullopt);
}

// static
ScreenshotArea ScreenshotArea::CreateForWindow(const aura::Window* window) {
  return ScreenshotArea(ScreenshotType::kWindow, window, base::nullopt);
}

// static
ScreenshotArea ScreenshotArea::CreateForPartialWindow(
    const aura::Window* window,
    const gfx::Rect rect) {
  return ScreenshotArea(ScreenshotType::kPartialWindow, window, rect);
}

ScreenshotArea::ScreenshotArea(const ScreenshotArea& area) = default;

ScreenshotArea::ScreenshotArea(ScreenshotType type,
                               const aura::Window* window,
                               base::Optional<const gfx::Rect> rect)
    : type(type), window(window), rect(rect) {}
