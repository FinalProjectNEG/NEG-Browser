// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ASH_SHELF_SHELF_NAVIGATION_WIDGET_H_
#define ASH_SHELF_SHELF_NAVIGATION_WIDGET_H_

#include <memory>

#include "ash/ash_export.h"
#include "ash/shelf/shelf_component.h"
#include "ui/views/accessible_pane_view.h"
#include "ui/views/widget/widget.h"
#include "ui/views/widget/widget_delegate.h"

namespace aura {
class Window;
}

namespace views {
class BoundsAnimator;
}

namespace ash {
class BackButton;
class HomeButton;
enum class HotseatState;
class NavigationButtonAnimationMetricsReporter;
class Shelf;
class ShelfView;

// The shelf navigation widget holds the home button and (when in tablet mode)
// the back button.
class ASH_EXPORT ShelfNavigationWidget : public ShelfComponent,
                                         public views::Widget {
 public:
  class TestApi {
   public:
    explicit TestApi(ShelfNavigationWidget* widget);
    ~TestApi();

    // Whether the home button view is visible.
    bool IsHomeButtonVisible() const;

    // Whether the back button view is visible.
    bool IsBackButtonVisible() const;

    views::BoundsAnimator* GetBoundsAnimator();

   private:
    ShelfNavigationWidget* navigation_widget_;
  };

  ShelfNavigationWidget(Shelf* shelf, ShelfView* shelf_view);
  ~ShelfNavigationWidget() override;

  // Initializes the widget, sets its contents view and basic properties.
  void Initialize(aura::Window* container);

  // views::Widget:
  void OnMouseEvent(ui::MouseEvent* event) override;
  void OnScrollEvent(ui::ScrollEvent* event) override;
  bool OnNativeWidgetActivationChanged(bool active) override;
  void OnGestureEvent(ui::GestureEvent* event) override;

  // Getter for the back button view - nullptr if the back button should not be
  // shown for the current shelf configuration.
  BackButton* GetBackButton() const;

  // Getter for the home button view - nullptr if the home button should not be
  // shown for  the current shelf configuration.
  HomeButton* GetHomeButton() const;

  // Sets whether the last focusable child (instead of the first) should be
  // focused when activating this widget.
  void SetDefaultLastFocusableChild(bool default_last_focusable_child);

  // ShelfComponent:
  void CalculateTargetBounds() override;
  gfx::Rect GetTargetBounds() const override;
  void UpdateLayout(bool animate) override;
  void UpdateTargetBoundsForGesture(int shelf_position) override;

  // Returns the visible part's bounds in screen coordinates.
  gfx::Rect GetVisibleBounds() const;

  // Do preparations before setting focus on the navigation widget.
  void PrepareForGettingFocus(bool last_element);

  // Called when shelf layout manager detects a locale change. Reloads the
  // home and back button tooltips and accessibility name strings.
  void HandleLocaleChange();

  const views::BoundsAnimator* bounds_animator_for_test() const {
    return bounds_animator_.get();
  }

 private:
  class Delegate;

  void UpdateButtonVisibility(
      views::View* button,
      bool visible,
      bool animate,
      NavigationButtonAnimationMetricsReporter* metrics_reporter,
      HotseatState target_hotseat_state);

  // Returns the clip rectangle.
  gfx::Rect CalculateClipRect() const;

  // Returns the ideal size of the whole widget or the visible area only when
  // |only_visible_area| is true.
  gfx::Size CalculateIdealSize(bool only_visible_area) const;

  // Returns the number of visible control buttons.
  int CalculateButtonCount() const;

  Shelf* shelf_ = nullptr;
  Delegate* delegate_ = nullptr;

  // In tablet mode with hotseat enabled, |clip_rect_| is used to hide the
  // invisible widget part.
  gfx::Rect clip_rect_;

  // The target widget bounds in screen coordinates.
  gfx::Rect target_bounds_;

  std::unique_ptr<views::BoundsAnimator> bounds_animator_;

  // Animation metrics reporter for back button animations. Owned by the
  // Widget to ensure it outlives the BackButton view.
  std::unique_ptr<NavigationButtonAnimationMetricsReporter>
      back_button_metrics_reporter_;

  // Animation metrics reporter for home button animations. Owned by the
  // Widget to ensure it outlives the HomeButton view.
  std::unique_ptr<NavigationButtonAnimationMetricsReporter>
      home_button_metrics_reporter_;

  DISALLOW_COPY_AND_ASSIGN(ShelfNavigationWidget);
};

}  // namespace ash

#endif  // ASH_SHELF_SHELF_NAVIGATION_WIDGET_H_
