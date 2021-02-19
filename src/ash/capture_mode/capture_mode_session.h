// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ASH_CAPTURE_MODE_CAPTURE_MODE_SESSION_H_
#define ASH_CAPTURE_MODE_CAPTURE_MODE_SESSION_H_

#include <memory>

#include "ash/ash_export.h"
#include "ash/capture_mode/capture_mode_types.h"
#include "ash/public/cpp/tablet_mode_observer.h"
#include "ui/compositor/layer_delegate.h"
#include "ui/compositor/layer_owner.h"
#include "ui/events/event.h"
#include "ui/events/event_handler.h"
#include "ui/views/controls/button/button.h"
#include "ui/views/widget/widget.h"

namespace gfx {
class Canvas;
}  // namespace gfx

namespace ash {

class CaptureModeBarView;
class CaptureModeController;
class CaptureWindowObserver;

// Encapsulates an active capture mode session (i.e. an instance of this class
// lives as long as capture mode is active). It creates and owns the capture
// mode bar widget.
// The CaptureModeSession is a LayerOwner that owns a texture layer placed right
// beneath the layer of the bar widget. This layer is used to paint a dimming
// shield of the areas that won't be captured, and another bright region showing
// the one that will be.
class ASH_EXPORT CaptureModeSession : public ui::LayerOwner,
                                      public ui::LayerDelegate,
                                      public ui::EventHandler,
                                      public TabletModeObserver {
 public:
  // Creates the bar widget on the given |root| window.
  CaptureModeSession(CaptureModeController* controller, aura::Window* root);
  CaptureModeSession(const CaptureModeSession&) = delete;
  CaptureModeSession& operator=(const CaptureModeSession&) = delete;
  ~CaptureModeSession() override;

  // The vertical distance from the size label to the custom capture region.
  static constexpr int kSizeLabelYDistanceFromRegionDp = 8;

  // The vertical distance of the capture button from the capture region, if the
  // capture button does not fit inside the capture region.
  static constexpr int kCaptureButtonDistanceFromRegionDp = 24;

  aura::Window* current_root() const { return current_root_; }
  CaptureModeBarView* capture_mode_bar_view() const {
    return capture_mode_bar_view_;
  }
  views::Widget* dimensions_label_widget() {
    return dimensions_label_widget_.get();
  }
  bool is_selecting_region() const { return is_selecting_region_; }

  // Gets the current window selected for |kWindow| capture source. Returns
  // nullptr if no window is available for selection.
  aura::Window* GetSelectedWindow() const;

  // Called when either the capture source or type changes.
  void OnCaptureSourceChanged(CaptureModeSource new_source);
  void OnCaptureTypeChanged(CaptureModeType new_type);

  // Called when starting 3-seconds count down before recording video.
  void StartCountDown(base::OnceClosure countdown_finished_callback);

  // ui::LayerDelegate:
  void OnPaintLayer(const ui::PaintContext& context) override;
  void OnDeviceScaleFactorChanged(float old_device_scale_factor,
                                  float new_device_scale_factor) override {}

  // ui::EventHandler:
  void OnKeyEvent(ui::KeyEvent* event) override;
  void OnMouseEvent(ui::MouseEvent* event) override;
  void OnTouchEvent(ui::TouchEvent* event) override;

  // TabletModeObserver:
  void OnTabletModeStarted() override;
  void OnTabletModeEnded() override;

  views::Widget* capture_label_widget_for_testing() const {
    return capture_label_widget_.get();
  }

 private:
  // Gets the bounds of current window selected for |kWindow| capture source.
  gfx::Rect GetSelectedWindowBounds() const;

  // Ensures that the bar widget is on top of everything, and the overlay (which
  // is the |layer()| of this class that paints the capture region) is stacked
  // right below the bar.
  void RefreshStackingOrder(aura::Window* parent_container);

  // Paints the current capture region depending on the current capture source.
  void PaintCaptureRegion(gfx::Canvas* canvas);

  // Helper to unify mouse/touch events. Forwards events to the three below
  // functions and they are located on |capture_button_widget_|. Blocks events
  // from reaching other handlers, unless the event is located on
  // |capture_mode_bar_widget_|. |is_touch| signifies this is a touch event, and
  // we will use larger hit targets for the drag affordances.
  void OnLocatedEvent(ui::LocatedEvent* event, bool is_touch);

  // Handles updating the select region UI.
  void OnLocatedEventPressed(const gfx::Point& location_in_root, bool is_touch);
  void OnLocatedEventDragged(const gfx::Point& location_in_root);
  void OnLocatedEventReleased(const gfx::Point& location_in_root);

  // Updates the capture region and the capture region widgets depending on the
  // value of |is_resizing|.
  void UpdateCaptureRegion(const gfx::Rect& new_capture_region,
                           bool is_resizing);

  // Updates the dimensions label widget shown during a region capture session.
  // If not |is_resizing|, not a region capture session or the capture region is
  // empty, clear existing |dimensions_label_widget_|. Otherwise, create and
  // update the dimensions label.
  void UpdateDimensionsLabelWidget(bool is_resizing);

  // Updates the bounds of |dimensions_label_widget_| relative to the current
  // capture region. Both |dimensions_label_widget_| and its content view must
  // exist.
  void UpdateDimensionsLabelBounds();

  // Retrieves the anchor points on the current selected region associated with
  // |position|. The anchor points are described as the points that do not
  // change when resizing the capture region while dragging one of the drag
  // affordances. There is one anchor point if |position| is a vertex, and two
  // anchor points if |position| is an edge.
  std::vector<gfx::Point> GetAnchorPointsForPosition(FineTunePosition position);

  // Updates the capture label widget.
  void UpdateCaptureLabelWidget();
  void UpdateCaptureLabelWidgetBounds();

  // Returns true if the capture label should handle the event. |event_target|
  // is the window which is receiving the event. The capture label should handle
  // the event if its associated window is |event_target| and its capture button
  // child is visible.
  bool ShouldCaptureLabelHandleEvent(aura::Window* event_target);

  CaptureModeController* const controller_;

  // The current root window on which the capture session is active, which may
  // change if the user warps the cursor to another display in some situations.
  aura::Window* current_root_;

  views::Widget capture_mode_bar_widget_;

  // The content view of the above widget and owned by its views hierarchy.
  CaptureModeBarView* capture_mode_bar_view_;

  // Widget which displays capture region size during a region capture session.
  std::unique_ptr<views::Widget> dimensions_label_widget_;

  // Widget that shows an optional icon and a message in the middle of the
  // screen or in the middle of the capture region and prompts the user what to
  // do next. The icon and message can be different in different capture type
  // and source and can be empty in some cases. And in video capture mode, when
  // starting capturing, the widget will transform into a 3-second countdown
  // timer.
  std::unique_ptr<views::Widget> capture_label_widget_;

  // Stores the data needed to select a region during a region capture session.
  // This variable indicates if the user is currently selecting a region to
  // capture, it will be true when the first mouse/touch presses down and will
  // remain true until the mouse/touch releases up. After that, if the capture
  // region is non empty, the capture session will enter the fine tune phase,
  // where the user can reposition and resize the region with a lot of accuracy.
  bool is_selecting_region_ = false;

  // The location of the last press and drag events.
  gfx::Point initial_location_in_root_;
  gfx::Point previous_location_in_root_;
  // The position of the last press event during the fine tune phase drag.
  FineTunePosition fine_tune_position_;
  // The points that do not change during a fine tune resize. This is empty
  // when |fine_tune_position_| is kNone or kCenter, or if there is no drag
  // underway.
  std::vector<gfx::Point> anchor_points_;

  // Caches the old status of mouse warping before the session started to be
  // restored at the end.
  bool old_mouse_warp_status_;

  // Observer to observe the current selected to-be-captured window.
  std::unique_ptr<CaptureWindowObserver> capture_window_observer_;
};

}  // namespace ash

#endif  // ASH_CAPTURE_MODE_CAPTURE_MODE_SESSION_H_
