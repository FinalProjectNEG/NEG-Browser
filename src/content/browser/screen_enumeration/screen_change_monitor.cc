// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/screen_enumeration/screen_change_monitor.h"

#include "build/build_config.h"
#include "ui/display/screen.h"

namespace content {

ScreenChangeMonitor::ScreenChangeMonitor(
    base::RepeatingCallback<void(bool)> callback)
    : callback_(callback) {
// TODO(crbug.com/1071233): Investigate test failures (crashes?) on Fuchsia.
#if !defined(OS_FUCHSIA)
  if (display::Screen* screen = display::Screen::GetScreen()) {
    cached_displays_ = screen->GetAllDisplays();
    screen->AddObserver(this);
  }
#endif  // !OS_FUCHSIA
}

ScreenChangeMonitor::~ScreenChangeMonitor() {
  if (display::Screen* screen = display::Screen::GetScreen())
    screen->RemoveObserver(this);
}

void ScreenChangeMonitor::OnScreensChange() {
  if (display::Screen* screen = display::Screen::GetScreen()) {
    const auto& displays = screen->GetAllDisplays();
    if (cached_displays_ == displays)
      return;

    const bool is_multi_screen_changed =
        (cached_displays_.size() > 1) != (displays.size() > 1);
    cached_displays_ = displays;
    callback_.Run(is_multi_screen_changed);
  }
}

void ScreenChangeMonitor::OnDisplayAdded(const display::Display& new_display) {
  OnScreensChange();
}

void ScreenChangeMonitor::OnDisplayRemoved(
    const display::Display& old_display) {
  OnScreensChange();
}

void ScreenChangeMonitor::OnDisplayMetricsChanged(
    const display::Display& display,
    uint32_t changed_metrics) {
  // TODO(msw): Use the |changed_metrics| parameter to disregard some changes.
  OnScreensChange();
}

}  // namespace content
