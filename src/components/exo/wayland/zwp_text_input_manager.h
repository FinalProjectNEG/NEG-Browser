// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_EXO_WAYLAND_ZWP_TEXT_INPUT_MANAGER_H_
#define COMPONENTS_EXO_WAYLAND_ZWP_TEXT_INPUT_MANAGER_H_

#include <stdint.h>

struct wl_client;

namespace exo {
class XkbTracker;

namespace wayland {
class SerialTracker;

struct WaylandTextInputManager {
  WaylandTextInputManager(const XkbTracker* xkb_tracker,
                          SerialTracker* serial_tracker)
      : xkb_tracker(xkb_tracker), serial_tracker(serial_tracker) {}
  WaylandTextInputManager(const WaylandTextInputManager&) = delete;
  WaylandTextInputManager& operator=(const WaylandTextInputManager&) = delete;

  // Owned by Seat, which also always outlives zwp_text_input_manager.
  const XkbTracker* const xkb_tracker;

  // Owned by Server, which always outlives zwp_text_input_manager.
  SerialTracker* const serial_tracker;
};

void bind_text_input_manager(wl_client* client,
                             void* data,
                             uint32_t version,
                             uint32_t id);

}  // namespace wayland
}  // namespace exo

#endif  // COMPONENTS_EXO_WAYLAND_ZWP_TEXT_INPUT_MANAGER_H_
