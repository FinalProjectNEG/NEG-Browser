// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ASH_CAPTURE_MODE_CAPTURE_WINDOW_OBSERVER_H_
#define ASH_CAPTURE_MODE_CAPTURE_WINDOW_OBSERVER_H_

#include <set>

#include "ash/ash_export.h"
#include "ash/capture_mode/capture_mode_types.h"
#include "ui/aura/window_observer.h"
#include "ui/base/cursor/cursor.h"
#include "ui/gfx/geometry/point.h"
#include "ui/gfx/native_widget_types.h"
#include "ui/wm/public/activation_change_observer.h"

namespace aura {
class Window;
}  // namespace aura

namespace ash {

class CaptureModeSession;

// Class to observe the current selected to-be-captured window and update the
// capture region if applicable.
class ASH_EXPORT CaptureWindowObserver : public aura::WindowObserver,
                                         public ::wm::ActivationChangeObserver {
 public:
  CaptureWindowObserver(CaptureModeSession* capture_mode_session,
                        CaptureModeType type);
  CaptureWindowObserver(const CaptureWindowObserver&) = delete;
  CaptureWindowObserver& operator=(const CaptureWindowObserver&) = delete;

  ~CaptureWindowObserver() override;

  // Updates selected window depending on the mouse/touch event location. If
  // there is an eligible window under the current mouse/touch event location,
  // its bounds will be highlighted.
  void UpdateSelectedWindowAtPosition(const gfx::Point& location_in_screen);

  // Called when capture type changes. The mouse cursor image may update
  // accordingly.
  void OnCaptureTypeChanged(CaptureModeType new_type);

  // aura::WindowObserver:
  void OnWindowBoundsChanged(aura::Window* window,
                             const gfx::Rect& old_bounds,
                             const gfx::Rect& new_bounds,
                             ui::PropertyChangeReason reason) override;
  void OnWindowVisibilityChanging(aura::Window* window, bool visible) override;
  void OnWindowDestroying(aura::Window* window) override;

  // ::wm::ActivationChangeObserver:
  void OnWindowActivated(ActivationReason reason,
                         aura::Window* gained_active,
                         aura::Window* lost_active) override;

  aura::Window* window() { return window_; }

 private:
  void StartObserving(aura::Window* window);
  void StopObserving();

  // Updates selected window depending on the mouse/touch event location with
  // ignoring |ignore_windows|.
  void UpdateSelectedWindowAtPosition(
      const gfx::Point& location_in_screen,
      const std::set<aura::Window*>& ignore_windows);

  // Repaints the window capture region.
  void RepaintCaptureRegion();

  // Updates the mouse cursor to change it to a capture or record icon when the
  // mouse hovers over an eligible window.
  void UpdateMouseCursor();

  // Current observed window.
  aura::Window* window_ = nullptr;

  // Stores current mouse or touch location in screen coordinate.
  gfx::Point location_in_screen_;

  // Current capture type.
  CaptureModeType capture_type_;

  // True if the current cursor is locked by this.
  bool is_cursor_locked_ = false;
  const gfx::NativeCursor original_cursor_;

  // Pointer to current capture session. Not nullptr during this lifecycle.
  CaptureModeSession* const capture_mode_session_;
};

}  // namespace ash

#endif  // ASH_CAPTURE_MODE_CAPTURE_WINDOW_OBSERVER_H_
