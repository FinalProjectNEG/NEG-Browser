// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ash/wm/overview/scoped_overview_transform_window.h"

#include <algorithm>
#include <utility>

#include "ash/public/cpp/ash_features.h"
#include "ash/public/cpp/window_properties.h"
#include "ash/shell.h"
#include "ash/wm/overview/delayed_animation_observer_impl.h"
#include "ash/wm/overview/overview_constants.h"
#include "ash/wm/overview/overview_controller.h"
#include "ash/wm/overview/overview_grid.h"
#include "ash/wm/overview/overview_item.h"
#include "ash/wm/overview/overview_utils.h"
#include "ash/wm/overview/scoped_overview_animation_settings.h"
#include "ash/wm/splitview/split_view_controller.h"
#include "ash/wm/splitview/split_view_utils.h"
#include "ash/wm/tablet_mode/tablet_mode_controller.h"
#include "ash/wm/window_state.h"
#include "ash/wm/window_transient_descendant_iterator.h"
#include "ash/wm/window_util.h"
#include "base/bind.h"
#include "base/macros.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/thread_task_runner_handle.h"
#include "chromeos/ui/base/window_properties.h"
#include "ui/aura/client/aura_constants.h"
#include "ui/aura/client/transient_window_client.h"
#include "ui/aura/scoped_window_event_targeting_blocker.h"
#include "ui/aura/window.h"
#include "ui/compositor/layer.h"
#include "ui/compositor/layer_animation_observer.h"
#include "ui/compositor/layer_animator.h"
#include "ui/compositor/layer_observer.h"
#include "ui/gfx/geometry/insets.h"
#include "ui/gfx/geometry/rect_conversions.h"
#include "ui/gfx/geometry/vector2d_f.h"
#include "ui/gfx/transform_util.h"
#include "ui/views/layout/layout_provider.h"
#include "ui/views/widget/widget.h"
#include "ui/wm/core/coordinate_conversion.h"
#include "ui/wm/core/shadow_controller.h"
#include "ui/wm/core/window_animations.h"
#include "ui/wm/core/window_util.h"

namespace ash {

namespace {

// When set to true by tests makes closing the widget synchronous.
bool immediate_close_for_tests = false;

// Delay closing window to allow it to shrink and fade out.
constexpr int kCloseWindowDelayInMilliseconds = 150;

// Layer animation observer that is attached to a clip animation. Removes the
// clip and then self destructs after the animation is finished.
class RemoveClipObserver : public ui::ImplicitAnimationObserver,
                           public aura::WindowObserver {
 public:
  explicit RemoveClipObserver(aura::Window* window) : window_(window) {
    auto* animator = window_->layer()->GetAnimator();
    DCHECK(window_->layer()->GetAnimator()->is_animating());

    const auto original_transition_duration = animator->GetTransitionDuration();
    // Don't let |settings| overwrite the existing animation's duration.
    ui::ScopedLayerAnimationSettings settings{animator};
    settings.SetTransitionDuration(original_transition_duration);
    settings.AddObserver(this);
    window_->AddObserver(this);
  }
  RemoveClipObserver(const RemoveClipObserver&) = delete;
  RemoveClipObserver& operator=(const RemoveClipObserver&) = delete;
  ~RemoveClipObserver() override {
    StopObservingImplicitAnimations();
    window_->RemoveObserver(this);
    window_ = nullptr;
  }

 private:
  // ui::ImplicitAnimationObserver:
  void OnImplicitAnimationsCompleted() override {
    window_->layer()->SetClipRect(gfx::Rect());
    delete this;
  }

  // aura::WindowObserver:
  void OnWindowDestroying(aura::Window* window) override {
    DCHECK_EQ(window_, window);
    delete this;
  }

  // Guaranteed to be not null for the duration of |this|.
  aura::Window* window_;
};

// Clips |window| to |clip_rect|. If |clip_rect| is empty and there is an
// animation, animate first to a clip the size of |window|, then remove the
// clip. Otherwise the clip animation will clip away all the contents while it
// animates towards an empty clip rect (but not yet empty) before reshowing it
// once the clip rect is really empty. An empty clip rect means a request to
// clip nothing.
void ClipWindow(aura::Window* window, const gfx::Rect& clip_rect) {
  DCHECK(window);

  ui::LayerAnimator* animator = window->layer()->GetAnimator();
  const gfx::Rect target_clip_rect = animator->GetTargetClipRect();
  if (target_clip_rect == clip_rect)
    return;

  gfx::Rect new_clip_rect = clip_rect;
  if (new_clip_rect.IsEmpty() && animator->is_animating()) {
    // Animate to a clip the size of |window|. Create a self deleting object
    // which removes the clip when the animation is finished.
    new_clip_rect = gfx::Rect(window->bounds().size());
    new RemoveClipObserver(window);
  }

  window->layer()->SetClipRect(new_clip_rect);
}

}  // namespace

class ScopedOverviewTransformWindow::LayerCachingAndFilteringObserver
    : public ui::LayerObserver {
 public:
  explicit LayerCachingAndFilteringObserver(ui::Layer* layer) : layer_(layer) {
    layer_->AddObserver(this);
    layer_->AddCacheRenderSurfaceRequest();
    layer_->AddTrilinearFilteringRequest();
  }
  ~LayerCachingAndFilteringObserver() override {
    if (layer_) {
      layer_->RemoveTrilinearFilteringRequest();
      layer_->RemoveCacheRenderSurfaceRequest();
      layer_->RemoveObserver(this);
    }
  }

  // ui::LayerObserver overrides:
  void LayerDestroyed(ui::Layer* layer) override {
    layer_->RemoveObserver(this);
    layer_ = nullptr;
  }

 private:
  ui::Layer* layer_;

  DISALLOW_COPY_AND_ASSIGN(LayerCachingAndFilteringObserver);
};

ScopedOverviewTransformWindow::ScopedOverviewTransformWindow(
    OverviewItem* overview_item,
    aura::Window* window)
    : overview_item_(overview_item),
      window_(window),
      original_opacity_(window->layer()->GetTargetOpacity()),
      original_clip_rect_(window_->layer()->clip_rect()) {
  type_ = GetWindowDimensionsType(window->bounds().size());

  std::vector<aura::Window*> transient_children_to_hide;
  for (auto* transient : GetTransientTreeIterator(window)) {
    event_targeting_blocker_map_[transient] =
        std::make_unique<aura::ScopedWindowEventTargetingBlocker>(transient);

    transient->SetProperty(chromeos::kIsShowingInOverviewKey, true);

    // Add this as |aura::WindowObserver| for observing |kHideInOverviewKey|
    // property changes.
    window_observer_.Add(transient);

    // Hide transient children which have been specified to be hidden in
    // overview mode.
    if (transient != window && transient->GetProperty(kHideInOverviewKey))
      transient_children_to_hide.push_back(transient);
  }

  if (!transient_children_to_hide.empty())
    AddHiddenTransientWindows(std::move(transient_children_to_hide));

  aura::client::GetTransientWindowClient()->AddObserver(this);

  // Tablet mode grid layout has scrolling, so all windows must be stacked under
  // the current split view window if they share the same parent so that during
  // scrolls, they get scrolled underneath the split view window. The window
  // will be returned to its proper z-order on exiting overview if it is
  // activated.
  // TODO(sammiequon): This does not handle the case if either the snapped
  // window or this window is an always on top window.
  auto* split_view_controller =
      SplitViewController::Get(Shell::GetPrimaryRootWindow());
  if (ShouldUseTabletModeGridLayout() &&
      split_view_controller->InSplitViewMode()) {
    aura::Window* snapped_window =
        split_view_controller->GetDefaultSnappedWindow();
    if (window->parent() == snapped_window->parent()) {
      // Helper to get the z order of a window in its parent.
      auto get_z_order = [](aura::Window* window) -> size_t {
        for (size_t i = 0u; i < window->parent()->children().size(); ++i) {
          if (window == window->parent()->children()[i])
            return i;
        }
        NOTREACHED();
        return 0u;
      };

      if (get_z_order(window_) > get_z_order(snapped_window))
        window_->parent()->StackChildBelow(window_, snapped_window);
    }
  }
}

ScopedOverviewTransformWindow::~ScopedOverviewTransformWindow() {
  for (auto* transient : GetTransientTreeIterator(window_)) {
    transient->ClearProperty(chromeos::kIsShowingInOverviewKey);
    DCHECK(event_targeting_blocker_map_.contains(transient));
    event_targeting_blocker_map_.erase(transient);
  }

  if (!IsMinimized())
    UpdateRoundedCorners(/*show=*/false);
  aura::client::GetTransientWindowClient()->RemoveObserver(this);

  window_observer_.RemoveAll();
}

// static
float ScopedOverviewTransformWindow::GetItemScale(const gfx::SizeF& source,
                                                  const gfx::SizeF& target,
                                                  int top_view_inset,
                                                  int title_height) {
  return std::min(2.0f, (target.height() - title_height) /
                            (source.height() - top_view_inset));
}

// static
OverviewGridWindowFillMode
ScopedOverviewTransformWindow::GetWindowDimensionsType(const gfx::Size& size) {
  if (size.width() > size.height() * kExtremeWindowRatioThreshold)
    return OverviewGridWindowFillMode::kLetterBoxed;

  if (size.height() > size.width() * kExtremeWindowRatioThreshold)
    return OverviewGridWindowFillMode::kPillarBoxed;

  return OverviewGridWindowFillMode::kNormal;
}

void ScopedOverviewTransformWindow::RestoreWindow(bool reset_transform) {
  // Shadow controller may be null on shutdown.
  if (Shell::Get()->shadow_controller())
    Shell::Get()->shadow_controller()->UpdateShadowForWindow(window_);

  if (IsMinimized()) {
    // Minimized windows may have had their transforms altered by swiping up
    // from the shelf.
    SetTransform(window_, gfx::Transform());
    return;
  }

  if (reset_transform) {
    ScopedAnimationSettings animation_settings_list;
    BeginScopedAnimation(overview_item_->GetExitTransformAnimationType(),
                         &animation_settings_list);
    for (auto& settings : animation_settings_list) {
      auto exit_observer = std::make_unique<ExitAnimationObserver>();
      settings->AddObserver(exit_observer.get());
      if (window_->layer()->GetAnimator() == settings->GetAnimator())
        settings->AddObserver(new WindowTransformAnimationObserver(window_));
      Shell::Get()->overview_controller()->AddExitAnimationObserver(
          std::move(exit_observer));
    }

    // Use identity transform directly to reset window's transform when exiting
    // overview.
    SetTransform(window_, gfx::Transform());
    // Add requests to cache render surface and perform trilinear filtering for
    // the exit animation of overview mode. The requests will be removed when
    // the exit animation finishes.
    if (features::IsTrilinearFilteringEnabled()) {
      for (auto& settings : animation_settings_list) {
        settings->CacheRenderSurface();
        settings->TrilinearFiltering();
      }
    }
  }

  ScopedOverviewAnimationSettings animation_settings(
      overview_item_->GetExitOverviewAnimationType(), window_);
  SetOpacity(original_opacity_);
  SetClipping({ClippingType::kExit, gfx::SizeF()});
}

void ScopedOverviewTransformWindow::BeginScopedAnimation(
    OverviewAnimationType animation_type,
    ScopedAnimationSettings* animation_settings) {
  if (animation_type == OVERVIEW_ANIMATION_NONE)
    return;

  for (auto* window : window_util::GetVisibleTransientTreeIterator(window_)) {
    auto settings = std::make_unique<ScopedOverviewAnimationSettings>(
        animation_type, window);
    settings->DeferPaint();

    // Create an EnterAnimationObserver if this is an enter overview layout
    // animation.
    if (animation_type == OVERVIEW_ANIMATION_LAYOUT_OVERVIEW_ITEMS_ON_ENTER) {
      auto enter_observer = std::make_unique<EnterAnimationObserver>();
      settings->AddObserver(enter_observer.get());
      Shell::Get()->overview_controller()->AddEnterAnimationObserver(
          std::move(enter_observer));
    }

    animation_settings->push_back(std::move(settings));
  }
}

bool ScopedOverviewTransformWindow::Contains(const aura::Window* target) const {
  for (auto* window : GetTransientTreeIterator(window_)) {
    if (window->Contains(target))
      return true;
  }

  if (!IsMinimized())
    return false;

  // A minimized window's item_widget_ may have already been destroyed.
  const auto* item_widget = overview_item_->item_widget();
  if (!item_widget)
    return false;

  return item_widget->GetNativeWindow()->Contains(target);
}

gfx::RectF ScopedOverviewTransformWindow::GetTransformedBounds() const {
  return window_util::GetTransformedBounds(window_, GetTopInset());
}

int ScopedOverviewTransformWindow::GetTopInset() const {
  // Mirror window doesn't have insets.
  if (IsMinimized())
    return 0;
  for (auto* window : window_util::GetVisibleTransientTreeIterator(window_)) {
    // If there are regular windows in the transient ancestor tree, all those
    // windows are shown in the same overview item and the header is not masked.
    if (window != window_ &&
        window->type() == aura::client::WINDOW_TYPE_NORMAL) {
      return 0;
    }
  }
  return window_->GetProperty(aura::client::kTopViewInset);
}

void ScopedOverviewTransformWindow::SetOpacity(float opacity) {
  for (auto* window :
       window_util::GetVisibleTransientTreeIterator(GetOverviewWindow()))
    window->layer()->SetOpacity(opacity);
}

void ScopedOverviewTransformWindow::SetClipping(
    const ClippingData& clipping_data) {
  gfx::SizeF size;
  switch (clipping_data.first) {
    case ClippingType::kEnter:
      size = gfx::SizeF(window_->bounds().size());
      break;
    case ClippingType::kExit:
      ClipWindow(window_, original_clip_rect_);
      return;
    case ClippingType::kCustom:
      size = clipping_data.second;
      if (size.IsEmpty()) {
        // Given size is empty so we fallback to the overview clipping, which is
        // the size of the window. The header will be accounted for below.
        size = gfx::SizeF(window_->bounds().size());
      } else {
        // Transform affects the clip rect, so take that into account.
        const gfx::Vector2dF scale =
            window_->layer()->GetTargetTransform().Scale2d();
        size.Scale(1 / scale.x(), 1 / scale.y());
      }
      break;
  }

  if (size.IsEmpty())
    return;

  gfx::Rect clip_rect(gfx::ToRoundedSize(size));
  // We add 1 to the top_inset, because in some cases, the header is not
  // clipped fully due to what seems to be a rounding error.
  // TODO(afakhry|sammiequon): Investigate a proper fix for this.
  const int top_inset = GetTopInset();
  if (top_inset > 0)
    clip_rect.Inset(gfx::Insets(top_inset + 1, 0, 0, 0));
  ClipWindow(window_, clip_rect);
}

gfx::RectF ScopedOverviewTransformWindow::ShrinkRectToFitPreservingAspectRatio(
    const gfx::RectF& rect,
    const gfx::RectF& bounds,
    int top_view_inset,
    int title_height) {
  DCHECK(!rect.IsEmpty());
  DCHECK_LE(top_view_inset, rect.height());
  const float scale =
      GetItemScale(rect.size(), bounds.size(), top_view_inset, title_height);
  const float horizontal_offset = 0.5 * (bounds.width() - scale * rect.width());
  const float width = bounds.width() - 2.f * horizontal_offset;
  const float vertical_offset = title_height - scale * top_view_inset;
  const float height =
      std::min(scale * rect.height(), bounds.height() - vertical_offset);
  gfx::RectF new_bounds(bounds.x() + horizontal_offset,
                        bounds.y() + vertical_offset, width, height);

  switch (type()) {
    case OverviewGridWindowFillMode::kLetterBoxed:
    case OverviewGridWindowFillMode::kPillarBoxed: {
      // Attempt to scale |rect| to fit |bounds|. Maintain the aspect ratio of
      // |rect|. Letter boxed windows' width will match |bounds|'s width and
      // pillar boxed windows' height will match |bounds|'s height.
      const bool is_pillar = type() == OverviewGridWindowFillMode::kPillarBoxed;
      const gfx::Rect window_bounds =
          ::wm::GetTransientRoot(window_)->GetBoundsInScreen();
      const float window_ratio =
          float{window_bounds.width()} / window_bounds.height();
      if (is_pillar) {
        const float new_x = height * window_ratio;
        new_bounds.set_width(new_x);
      } else {
        const float new_y = bounds.width() / window_ratio;
        new_bounds = bounds;
        new_bounds.Inset(0, title_height, 0, 0);
        new_bounds.ClampToCenteredSize(gfx::SizeF(bounds.width(), new_y));
      }
      break;
    }
    default:
      break;
  }

  // If we do not use whole numbers, there may be some artifacts drawn (i.e.
  // shadows, notches). This may be an effect of subpixel rendering. It's ok to
  // round it here since this is the last calculation (we don't have to worry
  // about roundoff error).
  return gfx::RectF(gfx::ToRoundedRect(new_bounds));
}

aura::Window* ScopedOverviewTransformWindow::GetOverviewWindow() const {
  if (IsMinimized())
    return overview_item_->item_widget()->GetNativeWindow();
  return window_;
}

void ScopedOverviewTransformWindow::Close() {
  if (immediate_close_for_tests) {
    CloseWidget();
    return;
  }

  base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&ScopedOverviewTransformWindow::CloseWidget,
                     weak_ptr_factory_.GetWeakPtr()),
      base::TimeDelta::FromMilliseconds(kCloseWindowDelayInMilliseconds));
}

bool ScopedOverviewTransformWindow::IsMinimized() const {
  return WindowState::Get(window_)->IsMinimized();
}

void ScopedOverviewTransformWindow::PrepareForOverview() {
  Shell::Get()->shadow_controller()->UpdateShadowForWindow(window_);

  // Add requests to cache render surface and perform trilinear filtering. The
  // requests will be removed in dtor. So the requests will be valid during the
  // enter animation and the whole time during overview mode. For the exit
  // animation of overview mode, we need to add those requests again.
  if (features::IsTrilinearFilteringEnabled()) {
    for (auto* window :
         window_util::GetVisibleTransientTreeIterator(GetOverviewWindow())) {
      cached_and_filtered_layer_observers_.push_back(
          std::make_unique<LayerCachingAndFilteringObserver>(window->layer()));
    }
  }
}

void ScopedOverviewTransformWindow::EnsureVisible() {
  original_opacity_ = 1.f;
}

void ScopedOverviewTransformWindow::UpdateWindowDimensionsType() {
  type_ = GetWindowDimensionsType(window_->bounds().size());
}

void ScopedOverviewTransformWindow::UpdateRoundedCorners(bool show) {
  // Hide the corners if minimized, OverviewItemView will handle showing the
  // rounded corners on the UI.
  DCHECK(!IsMinimized());

  ui::Layer* layer = window_->layer();
  const float scale = layer->transform().Scale2d().x();
  const int radius =
      views::LayoutProvider::Get()->GetCornerRadiusMetric(views::EMPHASIS_LOW);
  const gfx::RoundedCornersF radii(show ? (radius / scale) : 0.0f);
  layer->SetRoundedCornerRadius(radii);
  layer->SetIsFastRoundedCorner(true);
}

void ScopedOverviewTransformWindow::OnTransientChildWindowAdded(
    aura::Window* parent,
    aura::Window* transient_child) {
  if (parent != window_ && !::wm::HasTransientAncestor(parent, window_))
    return;

  DCHECK(!event_targeting_blocker_map_.contains(transient_child));
  event_targeting_blocker_map_[transient_child] =
      std::make_unique<aura::ScopedWindowEventTargetingBlocker>(
          transient_child);
  transient_child->SetProperty(chromeos::kIsShowingInOverviewKey, true);

  // Hide transient children which have been specified to be hidden in
  // overview mode.
  if (transient_child != window_ &&
      transient_child->GetProperty(kHideInOverviewKey))
    AddHiddenTransientWindows({transient_child});

  // Add this as |aura::WindowObserver| for observing |kHideInOverviewKey|
  // property changes.
  window_observer_.Add(transient_child);
}

void ScopedOverviewTransformWindow::OnWindowPropertyChanged(
    aura::Window* window,
    const void* key,
    intptr_t old) {
  if (key != kHideInOverviewKey)
    return;

  const auto current_value = window->GetProperty(kHideInOverviewKey);
  if (current_value == old)
    return;

  if (current_value) {
    AddHiddenTransientWindows({window});
  } else {
    hidden_transient_children_->RemoveWindow(window);
  }
}

void ScopedOverviewTransformWindow::AddHiddenTransientWindows(
    const std::vector<aura::Window*>& transient_windows) {
  if (!hidden_transient_children_) {
    hidden_transient_children_ = std::make_unique<ScopedOverviewHideWindows>(
        std::move(transient_windows), /*forced_hidden=*/true);
  } else {
    for (auto* window : transient_windows)
      hidden_transient_children_->AddWindow(window);
  }
}

void ScopedOverviewTransformWindow::OnTransientChildWindowRemoved(
    aura::Window* parent,
    aura::Window* transient_child) {
  if (parent != window_ && !::wm::HasTransientAncestor(parent, window_))
    return;

  transient_child->ClearProperty(chromeos::kIsShowingInOverviewKey);
  DCHECK(event_targeting_blocker_map_.contains(transient_child));
  event_targeting_blocker_map_.erase(transient_child);

  if (window_observer_.IsObserving(transient_child))
    window_observer_.Remove(transient_child);
}

// static
void ScopedOverviewTransformWindow::SetImmediateCloseForTests(bool immediate) {
  immediate_close_for_tests = immediate;
}

void ScopedOverviewTransformWindow::CloseWidget() {
  aura::Window* parent_window = ::wm::GetTransientRoot(window_);
  if (parent_window)
    window_util::CloseWidgetForWindow(parent_window);
}

}  // namespace ash
