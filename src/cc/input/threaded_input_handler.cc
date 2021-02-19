// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cc/input/threaded_input_handler.h"

#include <utility>
#include <vector>

#include "build/build_config.h"
#include "cc/base/features.h"
#include "cc/input/scroll_elasticity_helper.h"
#include "cc/input/scroll_utils.h"
#include "cc/input/snap_selection_strategy.h"
#include "cc/layers/viewport.h"
#include "cc/trees/compositor_commit_data.h"
#include "cc/trees/layer_tree_host_impl.h"
#include "cc/trees/layer_tree_impl.h"
#include "cc/trees/layer_tree_settings.h"
#include "cc/trees/property_tree.h"
#include "cc/trees/scroll_node.h"

#include "ui/gfx/geometry/point.h"
#include "ui/gfx/geometry/point_conversions.h"
#include "ui/gfx/geometry/point_f.h"
#include "ui/gfx/geometry/vector2d_f.h"

namespace cc {

namespace {

enum SlowScrollMetricThread { MAIN_THREAD, CC_THREAD };

void RecordCompositorSlowScrollMetric(ui::ScrollInputType type,
                                      SlowScrollMetricThread scroll_thread) {
  bool scroll_on_main_thread = (scroll_thread == MAIN_THREAD);
  if (type == ui::ScrollInputType::kWheel) {
    UMA_HISTOGRAM_BOOLEAN("Renderer4.CompositorWheelScrollUpdateThread",
                          scroll_on_main_thread);
  } else if (type == ui::ScrollInputType::kTouchscreen) {
    UMA_HISTOGRAM_BOOLEAN("Renderer4.CompositorTouchScrollUpdateThread",
                          scroll_on_main_thread);
  }
}

}  // namespace

InputHandlerCommitData::InputHandlerCommitData() = default;
InputHandlerCommitData::~InputHandlerCommitData() = default;

// static
base::WeakPtr<InputHandler> InputHandler::Create(
    CompositorDelegateForInput& compositor_delegate) {
  auto input_handler =
      std::make_unique<ThreadedInputHandler>(compositor_delegate);
  base::WeakPtr<InputHandler> input_handler_weak = input_handler->AsWeakPtr();
  compositor_delegate.BindToInputHandler(std::move(input_handler));
  return input_handler_weak;
}

ThreadedInputHandler::ThreadedInputHandler(
    CompositorDelegateForInput& compositor_delegate)
    : compositor_delegate_(compositor_delegate),
      scrollbar_controller_(std::make_unique<ScrollbarController>(
          &compositor_delegate_.GetImplDeprecated())) {}

ThreadedInputHandler::~ThreadedInputHandler() = default;

//
// =========== InputHandler Interface
//

base::WeakPtr<InputHandler> ThreadedInputHandler::AsWeakPtr() const {
  return weak_factory_.GetWeakPtr();
}

void ThreadedInputHandler::BindToClient(InputHandlerClient* client) {
  DCHECK(input_handler_client_ == nullptr);
  input_handler_client_ = client;
}

InputHandler::ScrollStatus ThreadedInputHandler::ScrollBegin(
    ScrollState* scroll_state,
    ui::ScrollInputType type) {
  DCHECK(scroll_state);
  DCHECK(scroll_state->delta_x() == 0 && scroll_state->delta_y() == 0);

  InputHandler::ScrollStatus scroll_status;
  scroll_status.main_thread_scrolling_reasons =
      MainThreadScrollingReason::kNotScrollingOnMain;
  TRACE_EVENT0("cc", "ThreadedInputHandler::ScrollBegin");

  // If this ScrollBegin is non-animated then ensure we cancel any ongoing
  // animated scrolls.
  // TODO(bokan): This preserves existing behavior when we had diverging
  // paths for animated and non-animated scrolls but we should probably
  // decide when it best makes sense to cancel a scroll animation (maybe
  // ScrollBy is a better place to do it).
  if (scroll_state->delta_granularity() ==
      ui::ScrollGranularity::kScrollByPrecisePixel) {
    compositor_delegate_.GetImplDeprecated()
        .mutator_host()
        ->ScrollAnimationAbort();
    scroll_animating_snap_target_ids_ = TargetSnapAreaElementIds();
  }

  if (CurrentlyScrollingNode() && type == latched_scroll_type_) {
    // It's possible we haven't yet cleared the CurrentlyScrollingNode if we
    // received a GSE but we're still animating the last scroll. If that's the
    // case, we'll simply un-defer the GSE and continue latching to the same
    // node.
    DCHECK(deferred_scroll_end_);
    deferred_scroll_end_ = false;
    return scroll_status;
  }

  ScrollNode* scrolling_node = nullptr;
  bool scroll_on_main_thread = false;

  // TODO(bokan): ClearCurrentlyScrollingNode shouldn't happen in ScrollBegin,
  // this should only happen in ScrollEnd. We should DCHECK here that the state
  // is cleared instead. https://crbug.com/1016229
  ClearCurrentlyScrollingNode();

  ElementId target_element_id = scroll_state->target_element_id();

  if (target_element_id && !scroll_state->is_main_thread_hit_tested()) {
    TRACE_EVENT_INSTANT0("cc", "Latched scroll node provided",
                         TRACE_EVENT_SCOPE_THREAD);
    // If the caller passed in an element_id we can skip all the hit-testing
    // bits and provide a node straight-away.
    scrolling_node = GetScrollTree().FindNodeFromElementId(target_element_id);

    // In unified scrolling, if we found a node we get to scroll it.
    if (!base::FeatureList::IsEnabled(features::kScrollUnification)) {
      // We still need to confirm the targeted node exists and can scroll on
      // the compositor.
      if (scrolling_node) {
        scroll_status = TryScroll(GetScrollTree(), scrolling_node);
        if (IsMainThreadScrolling(scroll_status, scrolling_node))
          scroll_on_main_thread = true;
      }
    }
  } else {
    ScrollNode* starting_node = nullptr;
    if (target_element_id) {
      TRACE_EVENT_INSTANT0("cc", "Unlatched scroll node provided",
                           TRACE_EVENT_SCOPE_THREAD);
      // We had an element id but we should still perform the walk up the
      // scroll tree from the targeted node to latch to a scroller that can
      // scroll in the given direction. This mode is only used when scroll
      // unification is enabled and the targeted scroller comes back from a
      // main thread hit test.
      DCHECK(scroll_state->data()->is_main_thread_hit_tested);
      DCHECK(base::FeatureList::IsEnabled(features::kScrollUnification));
      starting_node = GetScrollTree().FindNodeFromElementId(target_element_id);

      if (!starting_node) {
        // The main thread sent us an element_id that the compositor doesn't
        // have a scroll node for. This can happen in some racy conditions, a
        // freshly created scroller hasn't yet been committed or a
        // scroller-destroying commit beats the hit test back to the compositor
        // thread. However, these cases shouldn't be user perceptible.
        scroll_status.main_thread_scrolling_reasons =
            MainThreadScrollingReason::kNoScrollingLayer;
        scroll_status.thread = InputHandler::ScrollThread::SCROLL_IGNORED;
        return scroll_status;
      }
    } else {
      TRACE_EVENT_INSTANT0("cc", "Hit Testing for ScrollNode",
                           TRACE_EVENT_SCOPE_THREAD);
      gfx::Point viewport_point(scroll_state->position_x(),
                                scroll_state->position_y());
      gfx::PointF device_viewport_point =
          gfx::ScalePoint(gfx::PointF(viewport_point),
                          compositor_delegate_.DeviceScaleFactor());

      if (base::FeatureList::IsEnabled(features::kScrollUnification)) {
        if (scroll_state->data()->is_main_thread_hit_tested) {
          // The client should have discarded the scroll when the hit test came
          // back with an invalid element id. If we somehow get here, we should
          // drop the scroll as continuing could cause us to infinitely bounce
          // back and forth between here and hit testing on the main thread.
          NOTREACHED();
          scroll_status.main_thread_scrolling_reasons =
              MainThreadScrollingReason::kNoScrollingLayer;
          scroll_status.thread = InputHandler::ScrollThread::SCROLL_IGNORED;
          return scroll_status;
        }

        // Touch dragging the scrollbar requires falling back to main-thread
        // scrolling.
        // TODO(bokan): This could be trivially handled in the compositor by
        // the new ScrollbarController and should be removed.
        {
          LayerImpl* first_scrolling_layer_or_scrollbar =
              ActiveTree().FindFirstScrollingLayerOrScrollbarThatIsHitByPoint(
                  device_viewport_point);
          if (IsTouchDraggingScrollbar(first_scrolling_layer_or_scrollbar,
                                       type)) {
            TRACE_EVENT_INSTANT0("cc", "Scrollbar Scrolling",
                                 TRACE_EVENT_SCOPE_THREAD);
            scroll_status.thread =
                InputHandler::ScrollThread::SCROLL_ON_MAIN_THREAD;
            scroll_status.main_thread_scrolling_reasons =
                MainThreadScrollingReason::kScrollbarScrolling;
            return scroll_status;
          }
        }

        ScrollHitTestResult scroll_hit_test =
            HitTestScrollNode(device_viewport_point);

        if (!scroll_hit_test.hit_test_successful) {
          // This result tells the client that the compositor doesn't have
          // enough information to target this scroll. The client should
          // perform a hit test in Blink and call this method again, with the
          // ElementId of the hit-tested scroll node.
          TRACE_EVENT_INSTANT0("cc", "Request Main Thread Hit Test",
                               TRACE_EVENT_SCOPE_THREAD);
          scroll_status.thread =
              InputHandler::ScrollThread::SCROLL_ON_IMPL_THREAD;
          scroll_status.needs_main_thread_hit_test = true;
          return scroll_status;
        }

        starting_node = scroll_hit_test.scroll_node;
      } else {
        LayerImpl* layer_impl =
            ActiveTree().FindLayerThatIsHitByPoint(device_viewport_point);

        if (layer_impl) {
          LayerImpl* first_scrolling_layer_or_scrollbar =
              ActiveTree().FindFirstScrollingLayerOrScrollbarThatIsHitByPoint(
                  device_viewport_point);

          // Touch dragging the scrollbar requires falling back to main-thread
          // scrolling.
          if (IsTouchDraggingScrollbar(first_scrolling_layer_or_scrollbar,
                                       type)) {
            TRACE_EVENT_INSTANT0("cc", "Scrollbar Scrolling",
                                 TRACE_EVENT_SCOPE_THREAD);
            scroll_status.thread =
                InputHandler::ScrollThread::SCROLL_ON_MAIN_THREAD;
            scroll_status.main_thread_scrolling_reasons =
                MainThreadScrollingReason::kScrollbarScrolling;
            return scroll_status;
          } else if (!IsInitialScrollHitTestReliable(
                         layer_impl, first_scrolling_layer_or_scrollbar)) {
            TRACE_EVENT_INSTANT0("cc", "Failed Hit Test",
                                 TRACE_EVENT_SCOPE_THREAD);
            scroll_status.thread = InputHandler::ScrollThread::SCROLL_UNKNOWN;
            scroll_status.main_thread_scrolling_reasons =
                MainThreadScrollingReason::kFailedHitTest;
            return scroll_status;
          }
        }

        starting_node = FindScrollNodeForCompositedScrolling(
            device_viewport_point, layer_impl, &scroll_on_main_thread,
            &scroll_status.main_thread_scrolling_reasons);
      }
    }

    // The above finds the ScrollNode that's hit by the given point but we
    // still need to walk up the scroll tree looking for the first node that
    // can consume delta from the scroll state.
    scrolling_node = FindNodeToLatch(scroll_state, starting_node, type);
  }

  if (scroll_on_main_thread) {
    // Under scroll unification we can request a main thread hit test, but we
    // should never send scrolls to the main thread.
    DCHECK(!base::FeatureList::IsEnabled(features::kScrollUnification));

    RecordCompositorSlowScrollMetric(type, MAIN_THREAD);
    scroll_status.thread = InputHandler::ScrollThread::SCROLL_ON_MAIN_THREAD;
    return scroll_status;
  } else if (!scrolling_node) {
    scroll_status.main_thread_scrolling_reasons =
        MainThreadScrollingReason::kNoScrollingLayer;
    if (compositor_delegate_.GetSettings().is_layer_tree_for_subframe) {
      // OOPIFs never have a viewport scroll node so if we can't scroll
      // we need to be bubble up to the parent frame. This happens by
      // returning SCROLL_UNKNOWN.
      TRACE_EVENT_INSTANT0("cc", "Ignored - No ScrollNode (OOPIF)",
                           TRACE_EVENT_SCOPE_THREAD);
      scroll_status.thread = InputHandler::ScrollThread::SCROLL_UNKNOWN;
    } else {
      // If we didn't hit a layer above we'd usually fallback to the
      // viewport scroll node. However, there may not be one if a scroll
      // is received before the root layer has been attached. Chrome now
      // drops input until the first commit is received so this probably
      // can't happen in a typical browser session but there may still be
      // configurations where input is allowed prior to a commit.
      TRACE_EVENT_INSTANT0("cc", "Ignored - No ScrollNode",
                           TRACE_EVENT_SCOPE_THREAD);
      scroll_status.thread = InputHandler::ScrollThread::SCROLL_IGNORED;
    }
    return scroll_status;
  }

  DCHECK_EQ(scroll_status.main_thread_scrolling_reasons,
            MainThreadScrollingReason::kNotScrollingOnMain);
  DCHECK_EQ(scroll_status.thread,
            InputHandler::ScrollThread::SCROLL_ON_IMPL_THREAD);

  ActiveTree().SetCurrentlyScrollingNode(scrolling_node);

  DidLatchToScroller(*scroll_state, type);

  // If the viewport is scrolling and it cannot consume any delta hints, the
  // scroll event will need to get bubbled if the viewport is for a guest or
  // oopif.
  if (GetViewport().ShouldScroll(*CurrentlyScrollingNode()) &&
      !GetViewport().CanScroll(*CurrentlyScrollingNode(), *scroll_state)) {
    scroll_status.bubble = true;
  }

  return scroll_status;
}

InputHandler::ScrollStatus ThreadedInputHandler::RootScrollBegin(
    ScrollState* scroll_state,
    ui::ScrollInputType type) {
  TRACE_EVENT0("cc", "ThreadedInputHandler::RootScrollBegin");
  if (!OuterViewportScrollNode()) {
    InputHandler::ScrollStatus scroll_status;
    scroll_status.thread = InputHandler::ScrollThread::SCROLL_IGNORED;
    scroll_status.main_thread_scrolling_reasons =
        MainThreadScrollingReason::kNoScrollingLayer;
    return scroll_status;
  }

  scroll_state->data()->set_current_native_scrolling_element(
      OuterViewportScrollNode()->element_id);
  InputHandler::ScrollStatus scroll_status = ScrollBegin(scroll_state, type);

  // Since we provided an ElementId, there should never be a need to perform a
  // hit test.
  DCHECK(!scroll_status.needs_main_thread_hit_test);

  return scroll_status;
}

InputHandlerScrollResult ThreadedInputHandler::ScrollUpdate(
    ScrollState* scroll_state,
    base::TimeDelta delayed_by) {
  DCHECK(scroll_state);

  // The current_native_scrolling_element should only be set for ScrollBegin.
  DCHECK(!scroll_state->data()->current_native_scrolling_element());
  TRACE_EVENT2("cc", "ThreadedInputHandler::ScrollUpdate", "dx",
               scroll_state->delta_x(), "dy", scroll_state->delta_y());

  if (!CurrentlyScrollingNode())
    return InputHandlerScrollResult();

  last_scroll_update_state_ = *scroll_state;

  gfx::Vector2dF resolvedScrollDelta = ResolveScrollGranularityToPixels(
      *CurrentlyScrollingNode(),
      gfx::Vector2dF(scroll_state->delta_x(), scroll_state->delta_y()),
      scroll_state->delta_granularity());

  scroll_state->data()->delta_x = resolvedScrollDelta.x();
  scroll_state->data()->delta_y = resolvedScrollDelta.y();
  // The decision of whether or not we'll animate a scroll comes down to
  // whether the granularity is specified in precise pixels or not. Thus we
  // need to preserve a precise granularity if that's what was specified; all
  // others are animated and so can be resolved to regular pixels.
  if (scroll_state->delta_granularity() !=
      ui::ScrollGranularity::kScrollByPrecisePixel) {
    scroll_state->data()->delta_granularity =
        ui::ScrollGranularity::kScrollByPixel;
  }

  compositor_delegate_.AccumulateScrollDeltaForTracing(
      gfx::Vector2dF(scroll_state->delta_x(), scroll_state->delta_y()));

  compositor_delegate_.WillScrollContent(CurrentlyScrollingNode()->element_id);

  float initial_top_controls_offset = compositor_delegate_.GetImplDeprecated()
                                          .browser_controls_manager()
                                          ->ControlsTopOffset();

  ScrollLatchedScroller(scroll_state, delayed_by);

  bool did_scroll_x = scroll_state->caused_scroll_x();
  bool did_scroll_y = scroll_state->caused_scroll_y();
  did_scroll_x_for_scroll_gesture_ |= did_scroll_x;
  did_scroll_y_for_scroll_gesture_ |= did_scroll_y;
  bool did_scroll_content = did_scroll_x || did_scroll_y;
  if (did_scroll_content) {
    bool is_animated_scroll = ShouldAnimateScroll(*scroll_state);
    compositor_delegate_.DidScrollContent(CurrentlyScrollingNode()->element_id,
                                          is_animated_scroll);
  } else {
    overscroll_delta_for_main_thread_ +=
        gfx::Vector2dF(scroll_state->delta_x(), scroll_state->delta_y());
  }

  SetNeedsCommit();

  // Scrolling along an axis resets accumulated root overscroll for that axis.
  if (did_scroll_x)
    accumulated_root_overscroll_.set_x(0);
  if (did_scroll_y)
    accumulated_root_overscroll_.set_y(0);

  gfx::Vector2dF unused_root_delta;
  if (GetViewport().ShouldScroll(*CurrentlyScrollingNode())) {
    unused_root_delta =
        gfx::Vector2dF(scroll_state->delta_x(), scroll_state->delta_y());
  }

  // When inner viewport is unscrollable, disable overscrolls.
  if (auto* inner_viewport_scroll_node = InnerViewportScrollNode()) {
    unused_root_delta =
        UserScrollableDelta(*inner_viewport_scroll_node, unused_root_delta);
  }

  accumulated_root_overscroll_ += unused_root_delta;

  bool did_scroll_top_controls =
      initial_top_controls_offset != compositor_delegate_.GetImplDeprecated()
                                         .browser_controls_manager()
                                         ->ControlsTopOffset();

  InputHandlerScrollResult scroll_result;
  scroll_result.did_scroll = did_scroll_content || did_scroll_top_controls;
  scroll_result.did_overscroll_root = !unused_root_delta.IsZero();
  scroll_result.accumulated_root_overscroll = accumulated_root_overscroll_;
  scroll_result.unused_scroll_delta = unused_root_delta;
  scroll_result.overscroll_behavior =
      scroll_state->is_scroll_chain_cut()
          ? OverscrollBehavior(OverscrollBehavior::Type::kNone)
          : ActiveTree().overscroll_behavior();

  if (scroll_result.did_scroll) {
    // Scrolling can change the root scroll offset, so inform the synchronous
    // input handler.
    UpdateRootLayerStateForSynchronousInputHandler();
  }

  scroll_result.current_visual_offset =
      ScrollOffsetToVector2dF(GetVisualScrollOffset(*CurrentlyScrollingNode()));
  float scale_factor = ActiveTree().page_scale_factor_for_scroll();
  scroll_result.current_visual_offset.Scale(scale_factor);

  // Run animations which need to respond to updated scroll offset.
  compositor_delegate_.GetImplDeprecated().mutator_host()->TickScrollAnimations(
      compositor_delegate_.GetImplDeprecated()
          .CurrentBeginFrameArgs()
          .frame_time,
      GetScrollTree());

  return scroll_result;
}

void ThreadedInputHandler::ScrollEnd(bool should_snap) {
  scrollbar_controller_->ResetState();
  if (!CurrentlyScrollingNode())
    return;

  // Note that if we deferred the scroll end then we should not snap. We will
  // snap once we deliver the deferred scroll end.
  if (compositor_delegate_.GetImplDeprecated()
          .mutator_host()
          ->ImplOnlyScrollAnimatingElement()) {
    DCHECK(!deferred_scroll_end_);
    deferred_scroll_end_ = true;
    return;
  }

  if (should_snap && SnapAtScrollEnd()) {
    deferred_scroll_end_ = true;
    return;
  }

  DCHECK(latched_scroll_type_.has_value());

  compositor_delegate_.GetImplDeprecated()
      .browser_controls_manager()
      ->ScrollEnd();

  ClearCurrentlyScrollingNode();
  deferred_scroll_end_ = false;
  scroll_gesture_did_end_ = true;
  SetNeedsCommit();
}

void ThreadedInputHandler::RecordScrollBegin(
    ui::ScrollInputType input_type,
    ScrollBeginThreadState scroll_start_state) {
  auto tracker_type = GetTrackerTypeForScroll(input_type);
  DCHECK_NE(tracker_type, FrameSequenceTrackerType::kMaxType);

  // The main-thread is the 'scrolling thread' if:
  //   (1) the scroll is driven by the main thread, or
  //   (2) the scroll is driven by the compositor, but blocked on the main
  //       thread.
  // Otherwise, the compositor-thread is the 'scrolling thread'.
  // TODO(crbug.com/1060712): We should also count 'main thread' as the
  // 'scrolling thread' if the layer being scrolled has scroll-event handlers.
  FrameSequenceMetrics::ThreadType scrolling_thread;
  switch (scroll_start_state) {
    case ScrollBeginThreadState::kScrollingOnCompositor:
      scrolling_thread = FrameSequenceMetrics::ThreadType::kCompositor;
      break;
    case ScrollBeginThreadState::kScrollingOnMain:
    case ScrollBeginThreadState::kScrollingOnCompositorBlockedOnMain:
      scrolling_thread = FrameSequenceMetrics::ThreadType::kMain;
      break;
  }
  compositor_delegate_.GetImplDeprecated().frame_trackers().StartScrollSequence(
      tracker_type, scrolling_thread);
}

void ThreadedInputHandler::RecordScrollEnd(ui::ScrollInputType input_type) {
  compositor_delegate_.GetImplDeprecated().frame_trackers().StopSequence(
      GetTrackerTypeForScroll(input_type));
}

InputHandlerPointerResult ThreadedInputHandler::MouseMoveAt(
    const gfx::Point& viewport_point) {
  InputHandlerPointerResult result;
  if (compositor_delegate_.GetSettings()
          .compositor_threaded_scrollbar_scrolling) {
    result =
        scrollbar_controller_->HandlePointerMove(gfx::PointF(viewport_point));
  }

  // Early out if there are no animation controllers and avoid the hit test.
  // This happens on platforms without animated scrollbars.
  if (!compositor_delegate_.HasAnimatedScrollbars())
    return result;

  gfx::PointF device_viewport_point = gfx::ScalePoint(
      gfx::PointF(viewport_point), compositor_delegate_.DeviceScaleFactor());

  ScrollHitTestResult hit_test = HitTestScrollNode(device_viewport_point);

  ScrollNode* scroll_node = hit_test.scroll_node;

  // The hit test can fail in some cases, e.g. we don't know if a region of a
  // squashed layer has content or is empty.
  if (!hit_test.hit_test_successful || !scroll_node)
    return result;

  // Scrollbars for the viewport are registered with the outer viewport layer.
  if (scroll_node->scrolls_inner_viewport)
    scroll_node = OuterViewportScrollNode();

  ElementId scroll_element_id = scroll_node->element_id;
  ScrollbarAnimationController* new_animation_controller =
      compositor_delegate_.GetImplDeprecated()
          .ScrollbarAnimationControllerForElementId(scroll_element_id);
  if (scroll_element_id != scroll_element_id_mouse_currently_over_) {
    ScrollbarAnimationController* old_animation_controller =
        compositor_delegate_.GetImplDeprecated()
            .ScrollbarAnimationControllerForElementId(
                scroll_element_id_mouse_currently_over_);
    if (old_animation_controller)
      old_animation_controller->DidMouseLeave();

    scroll_element_id_mouse_currently_over_ = scroll_element_id;

    // Experiment: Enables will flash scrollbar when user move mouse enter a
    // scrollable area.
    if (compositor_delegate_.GetSettings().scrollbar_flash_when_mouse_enter &&
        new_animation_controller)
      new_animation_controller->DidScrollUpdate();
  }

  if (!new_animation_controller)
    return result;

  new_animation_controller->DidMouseMove(device_viewport_point);

  return result;
}

InputHandlerPointerResult ThreadedInputHandler::MouseDown(
    const gfx::PointF& viewport_point,
    bool shift_modifier) {
  ScrollbarAnimationController* animation_controller =
      compositor_delegate_.GetImplDeprecated()
          .ScrollbarAnimationControllerForElementId(
              scroll_element_id_mouse_currently_over_);
  if (animation_controller) {
    animation_controller->DidMouseDown();
    scroll_element_id_mouse_currently_captured_ =
        scroll_element_id_mouse_currently_over_;
  }

  InputHandlerPointerResult result;
  if (compositor_delegate_.GetSettings()
          .compositor_threaded_scrollbar_scrolling) {
    result = scrollbar_controller_->HandlePointerDown(viewport_point,
                                                      shift_modifier);
  }

  return result;
}

InputHandlerPointerResult ThreadedInputHandler::MouseUp(
    const gfx::PointF& viewport_point) {
  if (scroll_element_id_mouse_currently_captured_) {
    ScrollbarAnimationController* animation_controller =
        compositor_delegate_.GetImplDeprecated()
            .ScrollbarAnimationControllerForElementId(
                scroll_element_id_mouse_currently_captured_);

    scroll_element_id_mouse_currently_captured_ = ElementId();

    if (animation_controller)
      animation_controller->DidMouseUp();
  }

  InputHandlerPointerResult result;
  if (compositor_delegate_.GetSettings()
          .compositor_threaded_scrollbar_scrolling)
    result = scrollbar_controller_->HandlePointerUp(viewport_point);

  return result;
}

void ThreadedInputHandler::MouseLeave() {
  compositor_delegate_.DidMouseLeave();
  scroll_element_id_mouse_currently_over_ = ElementId();
}

ElementId ThreadedInputHandler::FindFrameElementIdAtPoint(
    const gfx::PointF& viewport_point) {
  gfx::PointF device_viewport_point = gfx::ScalePoint(
      gfx::PointF(viewport_point), compositor_delegate_.DeviceScaleFactor());
  return ActiveTree().FindFrameElementIdAtPoint(device_viewport_point);
}

void ThreadedInputHandler::RequestUpdateForSynchronousInputHandler() {
  UpdateRootLayerStateForSynchronousInputHandler();
}

void ThreadedInputHandler::SetSynchronousInputHandlerRootScrollOffset(
    const gfx::ScrollOffset& root_content_offset) {
  TRACE_EVENT2(
      "cc", "ThreadedInputHandler::SetSynchronousInputHandlerRootScrollOffset",
      "offset_x", root_content_offset.x(), "offset_y", root_content_offset.y());

  gfx::Vector2dF physical_delta =
      root_content_offset.DeltaFrom(GetViewport().TotalScrollOffset());
  physical_delta.Scale(ActiveTree().page_scale_factor_for_scroll());

  bool changed = !GetViewport()
                      .ScrollBy(physical_delta,
                                /*viewport_point=*/gfx::Point(),
                                /*is_direct_manipulation=*/false,
                                /*affect_browser_controls=*/false,
                                /*scroll_outer_viewport=*/true)
                      .consumed_delta.IsZero();
  if (!changed)
    return;

  compositor_delegate_.DidScrollContent(OuterViewportScrollNode()->element_id,
                                        /*is_animated_scroll=*/false);
  SetNeedsCommit();

  // After applying the synchronous input handler's scroll offset, tell it what
  // we ended up with.
  UpdateRootLayerStateForSynchronousInputHandler();

  compositor_delegate_.SetNeedsFullViewportRedraw();
}

void ThreadedInputHandler::PinchGestureBegin() {
  pinch_gesture_active_ = true;
  pinch_gesture_end_should_clear_scrolling_node_ = !CurrentlyScrollingNode();

  TRACE_EVENT_INSTANT1("cc", "SetCurrentlyScrollingNode PinchGestureBegin",
                       TRACE_EVENT_SCOPE_THREAD, "isNull",
                       OuterViewportScrollNode() ? false : true);
  ActiveTree().SetCurrentlyScrollingNode(OuterViewportScrollNode());
  compositor_delegate_.GetImplDeprecated()
      .browser_controls_manager()
      ->PinchBegin();
  compositor_delegate_.DidStartPinchZoom();
}

void ThreadedInputHandler::PinchGestureUpdate(float magnify_delta,
                                              const gfx::Point& anchor) {
  TRACE_EVENT0("cc", "ThreadedInputHandler::PinchGestureUpdate");
  if (!InnerViewportScrollNode())
    return;
  has_pinch_zoomed_ = true;
  GetViewport().PinchUpdate(magnify_delta, anchor);
  SetNeedsCommit();
  compositor_delegate_.DidUpdatePinchZoom();
  // Pinching can change the root scroll offset, so inform the synchronous input
  // handler.
  UpdateRootLayerStateForSynchronousInputHandler();
}

void ThreadedInputHandler::PinchGestureEnd(const gfx::Point& anchor,
                                           bool snap_to_min) {
  pinch_gesture_active_ = false;
  if (pinch_gesture_end_should_clear_scrolling_node_) {
    pinch_gesture_end_should_clear_scrolling_node_ = false;
    ClearCurrentlyScrollingNode();
  }
  GetViewport().PinchEnd(anchor, snap_to_min);
  compositor_delegate_.GetImplDeprecated()
      .browser_controls_manager()
      ->PinchEnd();
  SetNeedsCommit();
  compositor_delegate_.DidEndPinchZoom();
}

void ThreadedInputHandler::SetNeedsAnimateInput() {
  compositor_delegate_.GetImplDeprecated().SetNeedsAnimateInput();
}

bool ThreadedInputHandler::IsCurrentlyScrollingViewport() const {
  auto* node = CurrentlyScrollingNode();
  if (!node)
    return false;
  return GetViewport().ShouldScroll(*node);
}

EventListenerProperties ThreadedInputHandler::GetEventListenerProperties(
    EventListenerClass event_class) const {
  return ActiveTree().event_listener_properties(event_class);
}

bool ThreadedInputHandler::HasBlockingWheelEventHandlerAt(
    const gfx::Point& viewport_point) const {
  gfx::PointF device_viewport_point = gfx::ScalePoint(
      gfx::PointF(viewport_point), compositor_delegate_.DeviceScaleFactor());

  LayerImpl* layer_impl_with_wheel_event_handler =
      ActiveTree().FindLayerThatIsHitByPointInWheelEventHandlerRegion(
          device_viewport_point);

  return layer_impl_with_wheel_event_handler;
}

InputHandler::TouchStartOrMoveEventListenerType
ThreadedInputHandler::EventListenerTypeForTouchStartOrMoveAt(
    const gfx::Point& viewport_point,
    TouchAction* out_touch_action) {
  gfx::PointF device_viewport_point = gfx::ScalePoint(
      gfx::PointF(viewport_point), compositor_delegate_.DeviceScaleFactor());

  LayerImpl* layer_impl_with_touch_handler =
      ActiveTree().FindLayerThatIsHitByPointInTouchHandlerRegion(
          device_viewport_point);

  if (layer_impl_with_touch_handler == nullptr) {
    if (out_touch_action)
      *out_touch_action = TouchAction::kAuto;
    return InputHandler::TouchStartOrMoveEventListenerType::NO_HANDLER;
  }

  if (out_touch_action) {
    gfx::Transform layer_screen_space_transform =
        layer_impl_with_touch_handler->ScreenSpaceTransform();
    gfx::Transform inverse_layer_screen_space(
        gfx::Transform::kSkipInitialization);
    bool can_be_inversed =
        layer_screen_space_transform.GetInverse(&inverse_layer_screen_space);
    // Getting here indicates that |layer_impl_with_touch_handler| is non-null,
    // which means that the |hit| in FindClosestMatchingLayer() is true, which
    // indicates that the inverse is available.
    DCHECK(can_be_inversed);
    bool clipped = false;
    gfx::Point3F planar_point = MathUtil::ProjectPoint3D(
        inverse_layer_screen_space, device_viewport_point, &clipped);
    gfx::PointF hit_test_point_in_layer_space =
        gfx::PointF(planar_point.x(), planar_point.y());
    const auto& region = layer_impl_with_touch_handler->touch_action_region();
    gfx::Point point = gfx::ToRoundedPoint(hit_test_point_in_layer_space);
    *out_touch_action = region.GetAllowedTouchAction(point);
  }

  if (!CurrentlyScrollingNode())
    return InputHandler::TouchStartOrMoveEventListenerType::HANDLER;

  // Check if the touch start (or move) hits on the current scrolling layer or
  // its descendant. layer_impl_with_touch_handler is the layer hit by the
  // pointer and has an event handler, otherwise it is null. We want to compare
  // the most inner layer we are hitting on which may not have an event listener
  // with the actual scrolling layer.
  LayerImpl* layer_impl =
      ActiveTree().FindLayerThatIsHitByPoint(device_viewport_point);
  bool is_ancestor = IsScrolledBy(layer_impl, CurrentlyScrollingNode());
  return is_ancestor ? InputHandler::TouchStartOrMoveEventListenerType::
                           HANDLER_ON_SCROLLING_LAYER
                     : InputHandler::TouchStartOrMoveEventListenerType::HANDLER;
}

std::unique_ptr<SwapPromiseMonitor>
ThreadedInputHandler::CreateLatencyInfoSwapPromiseMonitor(
    ui::LatencyInfo* latency) {
  return compositor_delegate_.GetImplDeprecated()
      .CreateLatencyInfoSwapPromiseMonitor(latency);
}

std::unique_ptr<EventsMetricsManager::ScopedMonitor>
ThreadedInputHandler::GetScopedEventMetricsMonitor(
    std::unique_ptr<EventMetrics> event_metrics) {
  return compositor_delegate_.GetImplDeprecated().GetScopedEventMetricsMonitor(
      std::move(event_metrics));
}

ScrollElasticityHelper* ThreadedInputHandler::CreateScrollElasticityHelper() {
  DCHECK(!scroll_elasticity_helper_);
  if (compositor_delegate_.GetSettings().enable_elastic_overscroll) {
    scroll_elasticity_helper_.reset(
        ScrollElasticityHelper::CreateForLayerTreeHostImpl(
            &compositor_delegate_.GetImplDeprecated()));
  }
  return scroll_elasticity_helper_.get();
}

bool ThreadedInputHandler::GetScrollOffsetForLayer(ElementId element_id,
                                                   gfx::ScrollOffset* offset) {
  ScrollTree& scroll_tree = GetScrollTree();
  ScrollNode* scroll_node = scroll_tree.FindNodeFromElementId(element_id);
  if (!scroll_node)
    return false;
  *offset = scroll_tree.current_scroll_offset(element_id);
  return true;
}

bool ThreadedInputHandler::ScrollLayerTo(ElementId element_id,
                                         const gfx::ScrollOffset& offset) {
  ScrollTree& scroll_tree = GetScrollTree();
  ScrollNode* scroll_node = scroll_tree.FindNodeFromElementId(element_id);
  if (!scroll_node)
    return false;

  scroll_tree.ScrollBy(
      *scroll_node,
      ScrollOffsetToVector2dF(offset -
                              scroll_tree.current_scroll_offset(element_id)),
      &ActiveTree());
  return true;
}

bool ThreadedInputHandler::ScrollingShouldSwitchtoMainThread() {
  DCHECK(!base::FeatureList::IsEnabled(features::kScrollUnification));
  ScrollTree& scroll_tree = GetScrollTree();
  ScrollNode* scroll_node = scroll_tree.CurrentlyScrollingNode();

  if (!scroll_node)
    return true;

  for (; scroll_tree.parent(scroll_node);
       scroll_node = scroll_tree.parent(scroll_node)) {
    if (!!scroll_node->main_thread_scrolling_reasons)
      return true;
  }

  return false;
}

bool ThreadedInputHandler::GetSnapFlingInfoAndSetAnimatingSnapTarget(
    const gfx::Vector2dF& natural_displacement_in_viewport,
    gfx::Vector2dF* out_initial_position,
    gfx::Vector2dF* out_target_position) {
  ScrollNode* scroll_node = CurrentlyScrollingNode();
  if (!scroll_node || !scroll_node->snap_container_data.has_value())
    return false;
  const SnapContainerData& data = scroll_node->snap_container_data.value();

  float scale_factor = ActiveTree().page_scale_factor_for_scroll();
  gfx::Vector2dF natural_displacement_in_content =
      gfx::ScaleVector2d(natural_displacement_in_viewport, 1.f / scale_factor);

  gfx::ScrollOffset current_offset = GetVisualScrollOffset(*scroll_node);
  *out_initial_position = ScrollOffsetToVector2dF(current_offset);

  // CC side always uses fractional scroll deltas.
  bool use_fractional_offsets = true;
  gfx::ScrollOffset snap_offset;
  TargetSnapAreaElementIds snap_target_ids;
  std::unique_ptr<SnapSelectionStrategy> strategy =
      SnapSelectionStrategy::CreateForEndAndDirection(
          current_offset, gfx::ScrollOffset(natural_displacement_in_content),
          use_fractional_offsets);
  if (!data.FindSnapPosition(*strategy, &snap_offset, &snap_target_ids))
    return false;
  scroll_animating_snap_target_ids_ = snap_target_ids;

  *out_target_position = ScrollOffsetToVector2dF(snap_offset);
  out_target_position->Scale(scale_factor);
  out_initial_position->Scale(scale_factor);
  return true;
}

void ThreadedInputHandler::ScrollEndForSnapFling(bool did_finish) {
  ScrollNode* scroll_node = CurrentlyScrollingNode();
  // When a snap fling animation reaches its intended target then we update the
  // scrolled node's snap targets. This also ensures blink learns about the new
  // snap targets for this scrolling element.
  if (did_finish && scroll_node &&
      scroll_node->snap_container_data.has_value()) {
    scroll_node->snap_container_data.value().SetTargetSnapAreaElementIds(
        scroll_animating_snap_target_ids_);
    updated_snapped_elements_.insert(scroll_node->element_id);
    SetNeedsCommit();
  }
  scroll_animating_snap_target_ids_ = TargetSnapAreaElementIds();
  ScrollEnd(false /* should_snap */);
}

void ThreadedInputHandler::NotifyInputEvent() {
  compositor_delegate_.GetImplDeprecated().NotifyInputEvent();
}

//
// =========== InputDelegateForCompositor Interface
//

void ThreadedInputHandler::ProcessCommitDeltas(
    CompositorCommitData* commit_data) {
  DCHECK(commit_data);
  if (ActiveTree().LayerListIsEmpty())
    return;

  ElementId inner_viewport_scroll_element_id =
      InnerViewportScrollNode() ? InnerViewportScrollNode()->element_id
                                : ElementId();

  base::flat_set<ElementId> snapped_elements;
  updated_snapped_elements_.swap(snapped_elements);

  // Scroll commit data is stored in the scroll tree so it has its own method
  // for getting it.
  // TODO(bokan): It's a bug that CollectScrollDeltas is here, it means the
  // compositor cannot commit scroll changes without an InputHandler which it
  // should be able to. To move it back, we'll need to split out the
  // |snapped_elements| part of ScrollTree::CollectScrollDeltas though which is
  // an input responsibility.
  GetScrollTree().CollectScrollDeltas(
      commit_data, inner_viewport_scroll_element_id,
      compositor_delegate_.GetSettings().commit_fractional_scroll_deltas,
      snapped_elements);

  // Record and reset scroll source flags.
  DCHECK(!commit_data->manipulation_info);
  if (has_scrolled_by_wheel_)
    commit_data->manipulation_info |= kManipulationInfoWheel;
  if (has_scrolled_by_touch_)
    commit_data->manipulation_info |= kManipulationInfoTouch;
  if (has_scrolled_by_precisiontouchpad_)
    commit_data->manipulation_info |= kManipulationInfoPrecisionTouchPad;
  if (has_pinch_zoomed_)
    commit_data->manipulation_info |= kManipulationInfoPinchZoom;

  has_scrolled_by_wheel_ = false;
  has_scrolled_by_touch_ = false;
  has_scrolled_by_precisiontouchpad_ = false;
  has_pinch_zoomed_ = false;

  commit_data->scroll_gesture_did_end = scroll_gesture_did_end_;
  scroll_gesture_did_end_ = false;

  commit_data->overscroll_delta = overscroll_delta_for_main_thread_;
  overscroll_delta_for_main_thread_ = gfx::Vector2dF();

  // Use the |last_latched_scroller_| rather than the
  // |CurrentlyScrollingNode| since the latter may be cleared by a GSE before
  // we've committed these values to the main thread.
  // TODO(bokan): This is wrong - if we also started a scroll this frame then
  // this will clear this value for that scroll. https://crbug.com/1116780.
  commit_data->scroll_latched_element_id = last_latched_scroller_;
  if (commit_data->scroll_gesture_did_end)
    last_latched_scroller_ = ElementId();
}

void ThreadedInputHandler::TickAnimations(base::TimeTicks monotonic_time) {
  if (input_handler_client_) {
    // This does not set did_animate, because if the InputHandlerClient
    // changes anything it will be through the InputHandler interface which
    // does SetNeedsRedraw.
    input_handler_client_->Animate(monotonic_time);
  }
}

void ThreadedInputHandler::WillShutdown() {
  if (input_handler_client_) {
    input_handler_client_->WillShutdown();
    input_handler_client_ = nullptr;
  }

  if (scroll_elasticity_helper_)
    scroll_elasticity_helper_.reset();
}

void ThreadedInputHandler::WillDraw() {
  if (input_handler_client_)
    input_handler_client_->ReconcileElasticOverscrollAndRootScroll();
}

void ThreadedInputHandler::WillBeginImplFrame(const viz::BeginFrameArgs& args) {
  if (input_handler_client_) {
    scrollbar_controller_->WillBeginImplFrame();
    input_handler_client_->DeliverInputForBeginFrame(args);
  }
}

void ThreadedInputHandler::DidCommit() {
  // In high latency mode commit cannot finish within the same frame. We need to
  // flush input here to make sure they got picked up by |PrepareTiles()|.
  if (input_handler_client_ && compositor_delegate_.IsInHighLatencyMode())
    input_handler_client_->DeliverInputForHighLatencyMode();
}

void ThreadedInputHandler::DidActivatePendingTree() {
  // The previous scrolling node might no longer exist in the new tree.
  if (!CurrentlyScrollingNode())
    ClearCurrentlyScrollingNode();

  // Activation can change the root scroll offset, so inform the synchronous
  // input handler.
  UpdateRootLayerStateForSynchronousInputHandler();
}

void ThreadedInputHandler::RootLayerStateMayHaveChanged() {
  UpdateRootLayerStateForSynchronousInputHandler();
}

void ThreadedInputHandler::DidUnregisterScrollbar(
    ElementId scroll_element_id,
    ScrollbarOrientation orientation) {
  scrollbar_controller_->DidUnregisterScrollbar(scroll_element_id, orientation);
}

void ThreadedInputHandler::ScrollOffsetAnimationFinished() {
  TRACE_EVENT0("cc", "ThreadedInputHandler::ScrollOffsetAnimationFinished");
  // ScrollOffsetAnimationFinished is called in two cases:
  //  1- smooth scrolling animation is over (IsAnimatingForSnap == false).
  //  2- snap scroll animation is over (IsAnimatingForSnap == true).
  //
  //  Only for case (1) we should check and run snap scroll animation if needed.
  if (!IsAnimatingForSnap() && SnapAtScrollEnd())
    return;

  // The end of a scroll offset animation means that the scrolling node is at
  // the target offset.
  ScrollNode* scroll_node = CurrentlyScrollingNode();
  if (scroll_node && scroll_node->snap_container_data.has_value()) {
    scroll_node->snap_container_data.value().SetTargetSnapAreaElementIds(
        scroll_animating_snap_target_ids_);
    updated_snapped_elements_.insert(scroll_node->element_id);
    SetNeedsCommit();
  }
  scroll_animating_snap_target_ids_ = TargetSnapAreaElementIds();

  // Call scrollEnd with the deferred scroll end state when the scroll animation
  // completes after GSE arrival.
  if (deferred_scroll_end_) {
    ScrollEnd(/*should_snap=*/false);
    return;
  }
}

bool ThreadedInputHandler::IsCurrentlyScrolling() const {
  return CurrentlyScrollingNode();
}

ActivelyScrollingType ThreadedInputHandler::GetActivelyScrollingType() const {
  if (!CurrentlyScrollingNode())
    return ActivelyScrollingType::kNone;

  if (!last_scroll_update_state_)
    return ActivelyScrollingType::kNone;

  bool did_scroll_content =
      did_scroll_x_for_scroll_gesture_ || did_scroll_y_for_scroll_gesture_;

  if (!did_scroll_content)
    return ActivelyScrollingType::kNone;

  if (ShouldAnimateScroll(last_scroll_update_state_.value()))
    return ActivelyScrollingType::kAnimated;

  return ActivelyScrollingType::kPrecise;
}

ScrollNode* ThreadedInputHandler::CurrentlyScrollingNode() {
  return GetScrollTree().CurrentlyScrollingNode();
}

const ScrollNode* ThreadedInputHandler::CurrentlyScrollingNode() const {
  return GetScrollTree().CurrentlyScrollingNode();
}

ScrollTree& ThreadedInputHandler::GetScrollTree() {
  return compositor_delegate_.GetScrollTree();
}

ScrollTree& ThreadedInputHandler::GetScrollTree() const {
  return compositor_delegate_.GetScrollTree();
}

ScrollNode* ThreadedInputHandler::InnerViewportScrollNode() const {
  return ActiveTree().InnerViewportScrollNode();
}

ScrollNode* ThreadedInputHandler::OuterViewportScrollNode() const {
  return ActiveTree().OuterViewportScrollNode();
}

Viewport& ThreadedInputHandler::GetViewport() const {
  return compositor_delegate_.GetImplDeprecated().viewport();
}

void ThreadedInputHandler::SetNeedsCommit() {
  compositor_delegate_.SetNeedsCommit();
}

LayerTreeImpl& ThreadedInputHandler::ActiveTree() {
  DCHECK(compositor_delegate_.GetImplDeprecated().active_tree());
  return *compositor_delegate_.GetImplDeprecated().active_tree();
}

LayerTreeImpl& ThreadedInputHandler::ActiveTree() const {
  DCHECK(compositor_delegate_.GetImplDeprecated().active_tree());
  return *compositor_delegate_.GetImplDeprecated().active_tree();
}

FrameSequenceTrackerType ThreadedInputHandler::GetTrackerTypeForScroll(
    ui::ScrollInputType input_type) const {
  switch (input_type) {
    case ui::ScrollInputType::kWheel:
      return FrameSequenceTrackerType::kWheelScroll;
    case ui::ScrollInputType::kTouchscreen:
      return FrameSequenceTrackerType::kTouchScroll;
    case ui::ScrollInputType::kScrollbar:
      return FrameSequenceTrackerType::kScrollbarScroll;
    case ui::ScrollInputType::kAutoscroll:
      return FrameSequenceTrackerType::kMaxType;
  }
}

bool ThreadedInputHandler::IsMainThreadScrolling(
    const InputHandler::ScrollStatus& status,
    const ScrollNode* scroll_node) const {
  if (status.thread == InputHandler::ScrollThread::SCROLL_ON_MAIN_THREAD) {
    if (!!scroll_node->main_thread_scrolling_reasons) {
      DCHECK(MainThreadScrollingReason::MainThreadCanSetScrollReasons(
          status.main_thread_scrolling_reasons));
    } else {
      DCHECK(MainThreadScrollingReason::CompositorCanSetScrollReasons(
          status.main_thread_scrolling_reasons));
    }
    return true;
  }
  return false;
}

gfx::Vector2dF ThreadedInputHandler::ResolveScrollGranularityToPixels(
    const ScrollNode& scroll_node,
    const gfx::Vector2dF& scroll_delta,
    ui::ScrollGranularity granularity) {
  gfx::Vector2dF pixel_delta = scroll_delta;

  if (granularity == ui::ScrollGranularity::kScrollByPage) {
    // Page should use a percentage of the scroller so change the parameters
    // and let the percentage case below resolve it.
    granularity = ui::ScrollGranularity::kScrollByPercentage;
    pixel_delta.Scale(kMinFractionToStepWhenPaging);
  }

  if (granularity == ui::ScrollGranularity::kScrollByPercentage) {
    gfx::SizeF scroller_size = gfx::SizeF(scroll_node.container_bounds);

    gfx::SizeF viewport_size =
        InnerViewportScrollNode()
            ? gfx::SizeF(InnerViewportScrollNode()->container_bounds)
            : gfx::SizeF(ActiveTree().GetDeviceViewport().size());

    // Convert from rootframe coordinates to screen coordinates (physical
    // pixels).
    scroller_size.Scale(compositor_delegate_.PageScaleFactor());

    pixel_delta = ScrollUtils::ResolveScrollPercentageToPixels(
        pixel_delta, scroller_size, viewport_size);
  }

  return pixel_delta;
}

InputHandler::ScrollStatus ThreadedInputHandler::TryScroll(
    const ScrollTree& scroll_tree,
    ScrollNode* scroll_node) const {
  DCHECK(!base::FeatureList::IsEnabled(features::kScrollUnification));

  InputHandler::ScrollStatus scroll_status;
  scroll_status.main_thread_scrolling_reasons =
      MainThreadScrollingReason::kNotScrollingOnMain;
  if (scroll_node->main_thread_scrolling_reasons) {
    TRACE_EVENT1("cc", "LayerImpl::TryScroll: Failed ShouldScrollOnMainThread",
                 "MainThreadScrollingReason",
                 scroll_node->main_thread_scrolling_reasons);
    scroll_status.thread = InputHandler::ScrollThread::SCROLL_ON_MAIN_THREAD;
    scroll_status.main_thread_scrolling_reasons =
        scroll_node->main_thread_scrolling_reasons;
    return scroll_status;
  }

  gfx::Transform screen_space_transform =
      scroll_tree.ScreenSpaceTransform(scroll_node->id);
  if (!screen_space_transform.IsInvertible()) {
    TRACE_EVENT0("cc", "LayerImpl::TryScroll: Ignored NonInvertibleTransform");
    scroll_status.thread = InputHandler::ScrollThread::SCROLL_IGNORED;
    scroll_status.main_thread_scrolling_reasons =
        MainThreadScrollingReason::kNonInvertibleTransform;
    return scroll_status;
  }

  if (!scroll_node->scrollable) {
    TRACE_EVENT0("cc", "LayerImpl::tryScroll: Ignored not scrollable");
    scroll_status.thread = InputHandler::ScrollThread::SCROLL_IGNORED;
    scroll_status.main_thread_scrolling_reasons =
        MainThreadScrollingReason::kNotScrollable;
    return scroll_status;
  }

  // If an associated scrolling layer is not found, the scroll node must not
  // support impl-scrolling. The root, secondary root, and inner viewports
  // are all exceptions to this and may not have a layer because it is not
  // required for hit testing.
  if (scroll_node->id != ScrollTree::kRootNodeId &&
      scroll_node->id != ScrollTree::kSecondaryRootNodeId &&
      !scroll_node->scrolls_inner_viewport &&
      !ActiveTree().LayerByElementId(scroll_node->element_id)) {
    TRACE_EVENT0("cc",
                 "LayerImpl::tryScroll: Failed due to no scrolling layer");
    scroll_status.thread = InputHandler::ScrollThread::SCROLL_ON_MAIN_THREAD;
    scroll_status.main_thread_scrolling_reasons =
        MainThreadScrollingReason::kNonFastScrollableRegion;
    return scroll_status;
  }

  // The a viewport node should be scrolled even if it has no scroll extent
  // since it'll scroll using the Viewport class which will generate browser
  // controls movement and overscroll delta.
  gfx::ScrollOffset max_scroll_offset =
      scroll_tree.MaxScrollOffset(scroll_node->id);
  if (max_scroll_offset.x() <= 0 && max_scroll_offset.y() <= 0 &&
      !GetViewport().ShouldScroll(*scroll_node)) {
    TRACE_EVENT0("cc",
                 "LayerImpl::tryScroll: Ignored. Technically scrollable,"
                 " but has no affordance in either direction.");
    scroll_status.thread = InputHandler::ScrollThread::SCROLL_IGNORED;
    scroll_status.main_thread_scrolling_reasons =
        MainThreadScrollingReason::kNotScrollable;
    return scroll_status;
  }

  scroll_status.thread = InputHandler::ScrollThread::SCROLL_ON_IMPL_THREAD;
  return scroll_status;
}

base::flat_set<int> ThreadedInputHandler::NonFastScrollableNodes(
    const gfx::PointF& device_viewport_point) const {
  base::flat_set<int> non_fast_scrollable_nodes;

  const auto& non_fast_layers =
      ActiveTree().FindLayersHitByPointInNonFastScrollableRegion(
          device_viewport_point);
  for (const auto* layer : non_fast_layers)
    non_fast_scrollable_nodes.insert(layer->scroll_tree_index());

  return non_fast_scrollable_nodes;
}

ScrollNode* ThreadedInputHandler::FindScrollNodeForCompositedScrolling(
    const gfx::PointF& device_viewport_point,
    LayerImpl* layer_impl,
    bool* scroll_on_main_thread,
    uint32_t* main_thread_scrolling_reasons) {
  DCHECK(!base::FeatureList::IsEnabled(features::kScrollUnification));
  DCHECK(scroll_on_main_thread);
  DCHECK(main_thread_scrolling_reasons);
  *main_thread_scrolling_reasons =
      MainThreadScrollingReason::kNotScrollingOnMain;

  const auto& non_fast_scrollable_nodes =
      NonFastScrollableNodes(device_viewport_point);

  // Walk up the hierarchy and look for a scrollable layer.
  ScrollTree& scroll_tree = GetScrollTree();
  ScrollNode* impl_scroll_node = nullptr;
  if (layer_impl) {
    // If this is a scrollbar layer, we can't directly use the associated
    // scroll_node (because the scroll_node associated with this layer will be
    // the owning scroller's parent). Instead, we first retrieve the scrollable
    // layer corresponding to the scrollbars owner and then use its
    // scroll_tree_index instead.
    int scroll_tree_index = layer_impl->scroll_tree_index();
    if (layer_impl->IsScrollbarLayer()) {
      LayerImpl* owner_scroll_layer = ActiveTree().LayerByElementId(
          ToScrollbarLayer(layer_impl)->scroll_element_id());
      scroll_tree_index = owner_scroll_layer->scroll_tree_index();
    }

    ScrollNode* scroll_node = scroll_tree.Node(scroll_tree_index);
    for (; scroll_tree.parent(scroll_node);
         scroll_node = scroll_tree.parent(scroll_node)) {
      // The content layer can also block attempts to scroll outside the main
      // thread.
      InputHandler::ScrollStatus status = TryScroll(scroll_tree, scroll_node);
      if (IsMainThreadScrolling(status, scroll_node)) {
        *scroll_on_main_thread = true;
        *main_thread_scrolling_reasons = status.main_thread_scrolling_reasons;
        return scroll_node;
      }

      if (non_fast_scrollable_nodes.contains(scroll_node->id)) {
        *scroll_on_main_thread = true;
        *main_thread_scrolling_reasons =
            MainThreadScrollingReason::kNonFastScrollableRegion;
        return scroll_node;
      }

      if (status.thread == InputHandler::ScrollThread::SCROLL_ON_IMPL_THREAD &&
          !impl_scroll_node) {
        impl_scroll_node = scroll_node;
      }
    }
  }

  // TODO(bokan): We shouldn't need this - ordinarily all scrolls should pass
  // through the outer viewport. If we aren't able to find a scroller we should
  // return nullptr here and ignore the scroll. However, it looks like on some
  // pages (reddit.com) we start scrolling from the inner node.
  if (!impl_scroll_node)
    impl_scroll_node = InnerViewportScrollNode();

  if (!impl_scroll_node)
    return nullptr;

  impl_scroll_node = GetNodeToScroll(impl_scroll_node);

  // Ensure that final scroll node scrolls on impl thread (crbug.com/625100)
  InputHandler::ScrollStatus status = TryScroll(scroll_tree, impl_scroll_node);
  if (IsMainThreadScrolling(status, impl_scroll_node)) {
    *scroll_on_main_thread = true;
    *main_thread_scrolling_reasons = status.main_thread_scrolling_reasons;
  } else if (non_fast_scrollable_nodes.contains(impl_scroll_node->id)) {
    *scroll_on_main_thread = true;
    *main_thread_scrolling_reasons =
        MainThreadScrollingReason::kNonFastScrollableRegion;
  }

  return impl_scroll_node;
}

ThreadedInputHandler::ScrollHitTestResult
ThreadedInputHandler::HitTestScrollNode(
    const gfx::PointF& device_viewport_point) const {
  ScrollHitTestResult result;
  result.scroll_node = nullptr;
  result.hit_test_successful = false;

  std::vector<const LayerImpl*> layers =
      ActiveTree().FindAllLayersUpToAndIncludingFirstScrollable(
          device_viewport_point);

  // It's theoretically possible to hit no layers or only non-scrolling layers.
  // e.g. an API hit test outside the viewport. In that case, just fallback to
  // scrolling the viewport.
  if (layers.empty() || !layers.back()->IsScrollerOrScrollbar()) {
    result.hit_test_successful = true;
    if (InnerViewportScrollNode())
      result.scroll_node = GetNodeToScroll(InnerViewportScrollNode());

    return result;
  }

  const LayerImpl* scroller_layer = layers.back();
  layers.pop_back();

  // Go through each layer in front of the scroller. Any of them may block
  // scrolling if they come from outside the scroller's scroll-subtree or if we
  // hit a non-fast-scrolling-region.
  for (const auto* layer_impl : layers) {
    DCHECK(!layer_impl->IsScrollbarLayer());

    // There are some cases where the hit layer may not be correct (e.g. layer
    // squashing, pointer-events:none layer) because the compositor doesn't
    // know what parts of the layer (if any) are actually visible to hit
    // testing. This is fine if we can determine that the scrolling node will
    // be the same regardless of whether we hit an opaque or transparent (to
    // hit testing) point of the layer. If the scrolling node may depend on
    // this, we have to get a hit test from the main thread.
    if (!IsInitialScrollHitTestReliable(layer_impl, scroller_layer)) {
      TRACE_EVENT_INSTANT0("cc", "Failed Hit Test", TRACE_EVENT_SCOPE_THREAD);
      return result;
    }

    // If we hit a non-fast scrollable region, that means there's some reason we
    // can't scroll in this region. Primarily, because there's another scroller
    // there that isn't composited and we don't know about so we'll return
    // nullptr in that case.
    if (ActiveTree().PointHitsNonFastScrollableRegion(device_viewport_point,
                                                      *layer_impl)) {
      return result;
    }
  }

  // If we hit a scrollbar layer, get the ScrollNode from its associated
  // scrolling layer, rather than directly from the scrollbar layer. The latter
  // would return the parent scroller's ScrollNode.
  if (scroller_layer->IsScrollbarLayer()) {
    scroller_layer = ActiveTree().LayerByElementId(
        ToScrollbarLayer(scroller_layer)->scroll_element_id());
    DCHECK(scroller_layer);
  } else {
    // We need to also make sure the scroller itself doesn't have a non-fast
    // scrolling region in the hit tested area.
    if (ActiveTree().PointHitsNonFastScrollableRegion(device_viewport_point,
                                                      *scroller_layer))
      return result;
  }

  ScrollNode* scroll_node =
      GetScrollTree().Node(scroller_layer->scroll_tree_index());

  result.scroll_node = GetNodeToScroll(scroll_node);
  result.hit_test_successful = true;
  return result;
}

// Requires falling back to main thread scrolling when it hit tests in scrollbar
// from touch.
bool ThreadedInputHandler::IsTouchDraggingScrollbar(
    LayerImpl* first_scrolling_layer_or_scrollbar,
    ui::ScrollInputType type) {
  return first_scrolling_layer_or_scrollbar &&
         first_scrolling_layer_or_scrollbar->IsScrollbarLayer() &&
         type == ui::ScrollInputType::kTouchscreen;
}

ScrollNode* ThreadedInputHandler::GetNodeToScroll(ScrollNode* node) const {
  // Blink has a notion of a "root scroller", which is the scroller in a page
  // that is considered to host the main content. Typically this will be the
  // document/LayoutView contents; however, in some situations Blink may choose
  // a sub-scroller (div, iframe) that should scroll with "viewport" behavior.
  // The "root scroller" is the node designated as the outer viewport in CC.
  // See third_party/blink/renderer/core/page/scrolling/README.md for details.
  //
  // "Viewport" scrolling ensures generation of overscroll events, top controls
  // movement, as well as correct multi-viewport panning in pinch-zoom and
  // other scenarios.  We use the viewport's outer scroll node to represent the
  // viewport in the scroll chain and apply scroll delta using CC's Viewport
  // class.
  //
  // Scrolling from position: fixed layers will chain directly up to the inner
  // viewport. Whether that should use the outer viewport (and thus the
  // Viewport class) to scroll or not depends on the root scroller scenario
  // because we don't want setting a root scroller to change the scroll chain
  // order. The |prevent_viewport_scrolling_from_inner| bit is used to
  // communicate that context.
  DCHECK(!node->prevent_viewport_scrolling_from_inner ||
         node->scrolls_inner_viewport);

  if (node->scrolls_inner_viewport &&
      !node->prevent_viewport_scrolling_from_inner) {
    DCHECK(OuterViewportScrollNode());
    return OuterViewportScrollNode();
  }

  return node;
}

bool ThreadedInputHandler::IsInitialScrollHitTestReliable(
    const LayerImpl* layer_impl,
    const LayerImpl* first_scrolling_layer_or_scrollbar) const {
  if (!first_scrolling_layer_or_scrollbar)
    return true;

  // Hit tests directly on a composited scrollbar are always reliable.
  if (layer_impl->IsScrollbarLayer()) {
    DCHECK(layer_impl == first_scrolling_layer_or_scrollbar);
    return true;
  }

  ScrollNode* closest_scroll_node = nullptr;
  auto& scroll_tree = GetScrollTree();
  ScrollNode* scroll_node = scroll_tree.Node(layer_impl->scroll_tree_index());
  for (; scroll_tree.parent(scroll_node);
       scroll_node = scroll_tree.parent(scroll_node)) {
    // TODO(bokan): |scrollable| appears to always be true in LayerList mode.
    // In non-LayerList, scroll hit tests should always be reliable because we
    // don't have situations where a layer can be hit testable but pass some
    // points through (e.g. squashing layers). Perhaps we can remove this
    // condition?
    if (scroll_node->scrollable) {
      closest_scroll_node = GetNodeToScroll(scroll_node);
      break;
    }
  }
  if (!closest_scroll_node)
    return false;

  // If |first_scrolling_layer_or_scrollbar| is not a scrollbar, it must be
  // a scrollabe layer with a scroll node. If this scroll node corresponds to
  // first scrollable ancestor along the scroll tree for |layer_impl|, the hit
  // test has not escaped to other areas of the scroll tree and is reliable.
  if (!first_scrolling_layer_or_scrollbar->IsScrollbarLayer()) {
    return closest_scroll_node->id ==
           first_scrolling_layer_or_scrollbar->scroll_tree_index();
  }

  return false;
}

gfx::Vector2dF ThreadedInputHandler::ComputeScrollDelta(
    const ScrollNode& scroll_node,
    const gfx::Vector2dF& delta) {
  ScrollTree& scroll_tree = GetScrollTree();
  float scale_factor = compositor_delegate_.PageScaleFactor();

  gfx::Vector2dF adjusted_scroll(delta);
  adjusted_scroll.Scale(1.f / scale_factor);
  adjusted_scroll = UserScrollableDelta(scroll_node, adjusted_scroll);

  gfx::ScrollOffset old_offset =
      scroll_tree.current_scroll_offset(scroll_node.element_id);
  gfx::ScrollOffset new_offset = scroll_tree.ClampScrollOffsetToLimits(
      old_offset + gfx::ScrollOffset(adjusted_scroll), scroll_node);

  gfx::ScrollOffset scrolled = new_offset - old_offset;
  return gfx::Vector2dF(scrolled.x(), scrolled.y());
}

bool ThreadedInputHandler::CalculateLocalScrollDeltaAndStartPoint(
    const ScrollNode& scroll_node,
    const gfx::PointF& viewport_point,
    const gfx::Vector2dF& viewport_delta,
    gfx::Vector2dF* out_local_scroll_delta,
    gfx::PointF* out_local_start_point /*= nullptr*/) {
  // Layers with non-invertible screen space transforms should not have passed
  // the scroll hit test in the first place.
  const gfx::Transform screen_space_transform =
      GetScrollTree().ScreenSpaceTransform(scroll_node.id);
  DCHECK(screen_space_transform.IsInvertible());
  gfx::Transform inverse_screen_space_transform(
      gfx::Transform::kSkipInitialization);
  bool did_invert =
      screen_space_transform.GetInverse(&inverse_screen_space_transform);
  // TODO(shawnsingh): With the advent of impl-side scrolling for non-root
  // layers, we may need to explicitly handle uninvertible transforms here.
  DCHECK(did_invert);

  float scale_from_viewport_to_screen_space =
      compositor_delegate_.DeviceScaleFactor();
  gfx::PointF screen_space_point =
      gfx::ScalePoint(viewport_point, scale_from_viewport_to_screen_space);

  gfx::Vector2dF screen_space_delta = viewport_delta;
  screen_space_delta.Scale(scale_from_viewport_to_screen_space);

  // Project the scroll start and end points to local layer space to find the
  // scroll delta in layer coordinates.
  bool start_clipped, end_clipped;
  gfx::PointF screen_space_end_point = screen_space_point + screen_space_delta;
  gfx::PointF local_start_point = MathUtil::ProjectPoint(
      inverse_screen_space_transform, screen_space_point, &start_clipped);
  gfx::PointF local_end_point = MathUtil::ProjectPoint(
      inverse_screen_space_transform, screen_space_end_point, &end_clipped);
  DCHECK(out_local_scroll_delta);
  *out_local_scroll_delta = local_end_point - local_start_point;

  if (out_local_start_point)
    *out_local_start_point = local_start_point;

  if (start_clipped || end_clipped)
    return false;

  return true;
}

gfx::Vector2dF ThreadedInputHandler::ScrollNodeWithViewportSpaceDelta(
    const ScrollNode& scroll_node,
    const gfx::PointF& viewport_point,
    const gfx::Vector2dF& viewport_delta) {
  ScrollTree& scroll_tree = GetScrollTree();
  gfx::PointF local_start_point;
  gfx::Vector2dF local_scroll_delta;
  if (!CalculateLocalScrollDeltaAndStartPoint(
          scroll_node, viewport_point, viewport_delta, &local_scroll_delta,
          &local_start_point)) {
    return gfx::Vector2dF();
  }

  bool scrolls_outer_viewport = scroll_node.scrolls_outer_viewport;
  TRACE_EVENT2("cc", "ScrollNodeWithViewportSpaceDelta", "delta_y",
               local_scroll_delta.y(), "is_outer", scrolls_outer_viewport);

  // Apply the scroll delta.
  gfx::ScrollOffset previous_offset =
      scroll_tree.current_scroll_offset(scroll_node.element_id);
  scroll_tree.ScrollBy(scroll_node, local_scroll_delta, &ActiveTree());
  gfx::ScrollOffset scrolled =
      scroll_tree.current_scroll_offset(scroll_node.element_id) -
      previous_offset;

  TRACE_EVENT_INSTANT1("cc", "ConsumedDelta", TRACE_EVENT_SCOPE_THREAD, "y",
                       scrolled.y());

  // Get the end point in the layer's content space so we can apply its
  // ScreenSpaceTransform.
  gfx::PointF actual_local_end_point =
      local_start_point + gfx::Vector2dF(scrolled.x(), scrolled.y());

  // Calculate the applied scroll delta in viewport space coordinates.
  bool end_clipped;
  const gfx::Transform screen_space_transform =
      scroll_tree.ScreenSpaceTransform(scroll_node.id);
  gfx::PointF actual_screen_space_end_point = MathUtil::MapPoint(
      screen_space_transform, actual_local_end_point, &end_clipped);
  DCHECK(!end_clipped);
  if (end_clipped)
    return gfx::Vector2dF();

  float scale_from_viewport_to_screen_space =
      compositor_delegate_.DeviceScaleFactor();
  gfx::PointF actual_viewport_end_point = gfx::ScalePoint(
      actual_screen_space_end_point, 1.f / scale_from_viewport_to_screen_space);
  return actual_viewport_end_point - viewport_point;
}

gfx::Vector2dF ThreadedInputHandler::ScrollNodeWithLocalDelta(
    const ScrollNode& scroll_node,
    const gfx::Vector2dF& local_delta) const {
  bool scrolls_outer_viewport = scroll_node.scrolls_outer_viewport;
  TRACE_EVENT2("cc", "ScrollNodeWithLocalDelta", "delta_y", local_delta.y(),
               "is_outer", scrolls_outer_viewport);
  float page_scale_factor = compositor_delegate_.PageScaleFactor();

  ScrollTree& scroll_tree = GetScrollTree();
  gfx::ScrollOffset previous_offset =
      scroll_tree.current_scroll_offset(scroll_node.element_id);
  gfx::Vector2dF delta = local_delta;
  delta.Scale(1.f / page_scale_factor);
  scroll_tree.ScrollBy(scroll_node, delta, &ActiveTree());
  gfx::ScrollOffset scrolled =
      scroll_tree.current_scroll_offset(scroll_node.element_id) -
      previous_offset;
  gfx::Vector2dF consumed_scroll(scrolled.x(), scrolled.y());
  consumed_scroll.Scale(page_scale_factor);
  TRACE_EVENT_INSTANT1("cc", "ConsumedDelta", TRACE_EVENT_SCOPE_THREAD, "y",
                       consumed_scroll.y());

  return consumed_scroll;
}

// TODO(danakj): Make this into two functions, one with delta, one with
// viewport_point, no bool required.
gfx::Vector2dF ThreadedInputHandler::ScrollSingleNode(
    const ScrollNode& scroll_node,
    const gfx::Vector2dF& delta,
    const gfx::Point& viewport_point,
    bool is_direct_manipulation) {
  gfx::Vector2dF adjusted_delta = UserScrollableDelta(scroll_node, delta);

  // Events representing direct manipulation of the screen (such as gesture
  // events) need to be transformed from viewport coordinates to local layer
  // coordinates so that the scrolling contents exactly follow the user's
  // finger. In contrast, events not representing direct manipulation of the
  // screen (such as wheel events) represent a fixed amount of scrolling so we
  // can just apply them directly, but the page scale factor is applied to the
  // scroll delta.
  if (is_direct_manipulation) {
    // For touch-scroll we need to scale the delta here, as the transform tree
    // won't know anything about the external page scale factors used by OOPIFs.
    gfx::Vector2dF scaled_delta(adjusted_delta);
    scaled_delta.Scale(1 / ActiveTree().external_page_scale_factor());
    return ScrollNodeWithViewportSpaceDelta(
        scroll_node, gfx::PointF(viewport_point), scaled_delta);
  }
  return ScrollNodeWithLocalDelta(scroll_node, adjusted_delta);
}

void ThreadedInputHandler::ScrollLatchedScroller(ScrollState* scroll_state,
                                                 base::TimeDelta delayed_by) {
  DCHECK(CurrentlyScrollingNode());
  DCHECK(scroll_state);
  DCHECK(latched_scroll_type_.has_value());

  ScrollNode& scroll_node = *CurrentlyScrollingNode();
  const gfx::Vector2dF delta(scroll_state->delta_x(), scroll_state->delta_y());
  TRACE_EVENT2("cc", "ThreadedInputHandler::ScrollLatchedScroller", "delta_x",
               delta.x(), "delta_y", delta.y());
  gfx::Vector2dF applied_delta;
  gfx::Vector2dF delta_applied_to_content;
  // TODO(tdresser): Use a more rational epsilon. See crbug.com/510550 for
  // details.
  const float kEpsilon = 0.1f;

  if (ShouldAnimateScroll(*scroll_state)) {
    DCHECK(!scroll_state->is_in_inertial_phase());

    if (ElementId id = compositor_delegate_.GetImplDeprecated()
                           .mutator_host()
                           ->ImplOnlyScrollAnimatingElement()) {
      TRACE_EVENT_INSTANT0("cc", "UpdateExistingAnimation",
                           TRACE_EVENT_SCOPE_THREAD);

      ScrollNode* animating_scroll_node =
          GetScrollTree().FindNodeFromElementId(id);
      DCHECK(animating_scroll_node);

      // Usually the CurrentlyScrollingNode will be the currently animating
      // one. The one exception is the inner viewport. Scrolling the combined
      // viewport will always set the outer viewport as the currently scrolling
      // node. However, if an animation is created on the inner viewport we
      // must use it when updating the animation curve.
      DCHECK(animating_scroll_node->id == scroll_node.id ||
             animating_scroll_node->scrolls_inner_viewport);

      bool animation_updated = ScrollAnimationUpdateTarget(
          *animating_scroll_node, delta, delayed_by);

      if (animation_updated) {
        // Because we updated the animation target, consume delta so we notify
        // the SwapPromiseMonitor to tell it that something happened that will
        // cause a swap in the future.  This will happen within the scope of
        // the dispatch of a gesture scroll update input event. If we don't
        // notify during the handling of the input event, the LatencyInfo
        // associated with the input event will not be added as a swap promise
        // and we won't get any swap results.
        applied_delta = delta;
      } else {
        TRACE_EVENT_INSTANT0("cc", "Didn't Update Animation",
                             TRACE_EVENT_SCOPE_THREAD);
      }
    } else {
      TRACE_EVENT_INSTANT0("cc", "CreateNewAnimation",
                           TRACE_EVENT_SCOPE_THREAD);
      if (scroll_node.scrolls_outer_viewport) {
        applied_delta = GetViewport().ScrollAnimated(delta, delayed_by);
      } else {
        applied_delta = ComputeScrollDelta(scroll_node, delta);
        compositor_delegate_.GetImplDeprecated().ScrollAnimationCreate(
            scroll_node, applied_delta, delayed_by);
      }
    }

    // Animated scrolling always applied only to the content (i.e. not to the
    // browser controls).
    delta_applied_to_content = delta;
  } else {
    gfx::Point viewport_point(scroll_state->position_x(),
                              scroll_state->position_y());
    if (GetViewport().ShouldScroll(scroll_node)) {
      // |scrolls_outer_viewport| will only ever be false if the scroll chains
      // up to the viewport without going through the outer viewport scroll
      // node. This is because we normally terminate the scroll chain at the
      // outer viewport node.  For example, if we start scrolling from an
      // element that's not a descendant of the root scroller. In these cases we
      // want to scroll *only* the inner viewport -- to allow panning while
      // zoomed -- but still use Viewport::ScrollBy to also move browser
      // controls if needed.
      Viewport::ScrollResult result = GetViewport().ScrollBy(
          delta, viewport_point, scroll_state->is_direct_manipulation(),
          latched_scroll_type_ != ui::ScrollInputType::kWheel,
          scroll_node.scrolls_outer_viewport);

      applied_delta = result.consumed_delta;
      delta_applied_to_content = result.content_scrolled_delta;
    } else {
      applied_delta = ScrollSingleNode(scroll_node, delta, viewport_point,
                                       scroll_state->is_direct_manipulation());
    }
  }

  // If the layer wasn't able to move, try the next one in the hierarchy.
  bool scrolled = std::abs(applied_delta.x()) > kEpsilon;
  scrolled = scrolled || std::abs(applied_delta.y()) > kEpsilon;
  if (!scrolled) {
    // TODO(bokan): This preserves existing behavior by not allowing tiny
    // scrolls to produce overscroll but is inconsistent in how delta gets
    // chained up. We need to clean this up.
    if (scroll_node.scrolls_outer_viewport)
      scroll_state->ConsumeDelta(applied_delta.x(), applied_delta.y());
    return;
  }

  if (!GetViewport().ShouldScroll(scroll_node)) {
    // If the applied delta is within 45 degrees of the input
    // delta, bail out to make it easier to scroll just one layer
    // in one direction without affecting any of its parents.
    float angle_threshold = 45;
    if (MathUtil::SmallestAngleBetweenVectors(applied_delta, delta) <
        angle_threshold) {
      applied_delta = delta;
    } else {
      // Allow further movement only on an axis perpendicular to the direction
      // in which the layer moved.
      applied_delta = MathUtil::ProjectVector(delta, applied_delta);
    }
    delta_applied_to_content = applied_delta;
  }

  scroll_state->set_caused_scroll(
      std::abs(delta_applied_to_content.x()) > kEpsilon,
      std::abs(delta_applied_to_content.y()) > kEpsilon);
  scroll_state->ConsumeDelta(applied_delta.x(), applied_delta.y());
}

bool ThreadedInputHandler::CanPropagate(ScrollNode* scroll_node,
                                        float x,
                                        float y) {
  return (x == 0 || scroll_node->overscroll_behavior.x ==
                        OverscrollBehavior::Type::kAuto) &&
         (y == 0 || scroll_node->overscroll_behavior.y ==
                        OverscrollBehavior::Type::kAuto);
}

ScrollNode* ThreadedInputHandler::FindNodeToLatch(ScrollState* scroll_state,
                                                  ScrollNode* starting_node,
                                                  ui::ScrollInputType type) {
  ScrollTree& scroll_tree = GetScrollTree();
  ScrollNode* scroll_node = nullptr;
  for (ScrollNode* cur_node = starting_node; cur_node;
       cur_node = scroll_tree.parent(cur_node)) {
    if (GetViewport().ShouldScroll(*cur_node)) {
      // Don't chain scrolls past a viewport node. Once we reach that, we
      // should scroll using the appropriate viewport node which may not be
      // |cur_node|.
      scroll_node = GetNodeToScroll(cur_node);
      break;
    }

    if (!cur_node->scrollable)
      continue;

    // For UX reasons, autoscrolling should always latch to the top-most
    // scroller, even if it can't scroll in the initial direction.
    if (type == ui::ScrollInputType::kAutoscroll ||
        CanConsumeDelta(*scroll_state, *cur_node)) {
      scroll_node = cur_node;
      break;
    }

    float delta_x = scroll_state->is_beginning() ? scroll_state->delta_x_hint()
                                                 : scroll_state->delta_x();
    float delta_y = scroll_state->is_beginning() ? scroll_state->delta_y_hint()
                                                 : scroll_state->delta_y();

    if (!CanPropagate(cur_node, delta_x, delta_y)) {
      // If we reach a node with non-auto overscroll-behavior and we still
      // haven't latched, we must latch to it. Consider a fully scrolled node
      // with non-auto overscroll-behavior: we are not allowed to further
      // chain scroll delta passed to it in the current direction but if we
      // reverse direction we should scroll it so we must be latched to it.
      scroll_node = cur_node;
      scroll_state->set_is_scroll_chain_cut(true);
      break;
    }
  }

  return scroll_node;
}

void ThreadedInputHandler::UpdateRootLayerStateForSynchronousInputHandler() {
  if (!input_handler_client_)
    return;
  input_handler_client_->UpdateRootLayerStateForSynchronousInputHandler(
      ActiveTree().TotalScrollOffset(), ActiveTree().TotalMaxScrollOffset(),
      ActiveTree().ScrollableSize(), ActiveTree().current_page_scale_factor(),
      ActiveTree().min_page_scale_factor(),
      ActiveTree().max_page_scale_factor());
}

void ThreadedInputHandler::DidLatchToScroller(const ScrollState& scroll_state,
                                              ui::ScrollInputType type) {
  DCHECK(CurrentlyScrollingNode());
  deferred_scroll_end_ = false;
  compositor_delegate_.GetImplDeprecated()
      .browser_controls_manager()
      ->ScrollBegin();
  compositor_delegate_.GetImplDeprecated()
      .mutator_host()
      ->ScrollAnimationAbort();

  scroll_animating_snap_target_ids_ = TargetSnapAreaElementIds();
  last_latched_scroller_ = CurrentlyScrollingNode()->element_id;
  latched_scroll_type_ = type;
  last_scroll_begin_state_ = scroll_state;

  compositor_delegate_.DidStartScroll();
  RecordCompositorSlowScrollMetric(type, CC_THREAD);

  UpdateScrollSourceInfo(scroll_state, type);
}

bool ThreadedInputHandler::CanConsumeDelta(const ScrollState& scroll_state,
                                           const ScrollNode& scroll_node) {
  gfx::Vector2dF delta_to_scroll;
  if (scroll_state.is_beginning()) {
    delta_to_scroll = gfx::Vector2dF(scroll_state.delta_x_hint(),
                                     scroll_state.delta_y_hint());
  } else {
    delta_to_scroll =
        gfx::Vector2dF(scroll_state.delta_x(), scroll_state.delta_y());
  }

  if (delta_to_scroll == gfx::Vector2dF())
    return true;

  if (scroll_state.is_direct_manipulation()) {
    gfx::Vector2dF local_scroll_delta;
    if (!CalculateLocalScrollDeltaAndStartPoint(
            scroll_node,
            gfx::PointF(scroll_state.position_x(), scroll_state.position_y()),
            delta_to_scroll, &local_scroll_delta)) {
      return false;
    }
    delta_to_scroll = local_scroll_delta;
  } else {
    delta_to_scroll = ResolveScrollGranularityToPixels(
        scroll_node, delta_to_scroll, scroll_state.delta_granularity());
  }

  if (ComputeScrollDelta(scroll_node, delta_to_scroll) != gfx::Vector2dF())
    return true;

  return false;
}

bool ThreadedInputHandler::ShouldAnimateScroll(
    const ScrollState& scroll_state) const {
  if (!compositor_delegate_.GetSettings().enable_smooth_scroll)
    return false;

  bool has_precise_scroll_deltas = scroll_state.delta_granularity() ==
                                   ui::ScrollGranularity::kScrollByPrecisePixel;

#if defined(OS_MAC)
  if (has_precise_scroll_deltas)
    return false;

  // Mac does not smooth scroll wheel events (crbug.com/574283). We allow tests
  // to force it on.
  return latched_scroll_type_ == ui::ScrollInputType::kScrollbar
             ? true
             : force_smooth_wheel_scrolling_for_testing_;
#else
  return !has_precise_scroll_deltas;
#endif
}

bool ThreadedInputHandler::SnapAtScrollEnd() {
  ScrollNode* scroll_node = CurrentlyScrollingNode();
  if (!scroll_node || !scroll_node->snap_container_data.has_value())
    return false;

  SnapContainerData& data = scroll_node->snap_container_data.value();
  gfx::ScrollOffset current_position = GetVisualScrollOffset(*scroll_node);

  // You might think that if a scroll never received a scroll update we could
  // just drop the snap. However, if the GSB+GSE arrived while we were mid-snap
  // from a previous gesture, this would leave the scroller at a
  // non-snap-point.
  DCHECK(last_scroll_update_state_ || last_scroll_begin_state_);
  ScrollState& last_scroll_state = last_scroll_update_state_
                                       ? *last_scroll_update_state_
                                       : *last_scroll_begin_state_;

  bool imprecise_wheel_scrolling =
      latched_scroll_type_ == ui::ScrollInputType::kWheel &&
      last_scroll_state.delta_granularity() !=
          ui::ScrollGranularity::kScrollByPrecisePixel;
  gfx::ScrollOffset last_scroll_delta = last_scroll_state.DeltaOrHint();

  std::unique_ptr<SnapSelectionStrategy> strategy;

  if (imprecise_wheel_scrolling && !last_scroll_delta.IsZero()) {
    // This was an imprecise wheel scroll so use direction snapping.
    strategy = SnapSelectionStrategy::CreateForDirection(
        current_position, last_scroll_delta, true);
  } else {
    strategy = SnapSelectionStrategy::CreateForEndPosition(
        current_position, did_scroll_x_for_scroll_gesture_,
        did_scroll_y_for_scroll_gesture_);
  }

  gfx::ScrollOffset snap_position;
  TargetSnapAreaElementIds snap_target_ids;
  if (!data.FindSnapPosition(*strategy, &snap_position, &snap_target_ids))
    return false;

  // TODO(bokan): Why only on the viewport?
  if (GetViewport().ShouldScroll(*scroll_node)) {
    compositor_delegate_.WillScrollContent(scroll_node->element_id);
  }

  gfx::Vector2dF delta =
      ScrollOffsetToVector2dF(snap_position - current_position);
  bool did_animate = false;
  if (scroll_node->scrolls_outer_viewport) {
    gfx::Vector2dF scaled_delta(delta);
    scaled_delta.Scale(compositor_delegate_.PageScaleFactor());
    gfx::Vector2dF consumed_delta =
        GetViewport().ScrollAnimated(scaled_delta, base::TimeDelta());
    did_animate = !consumed_delta.IsZero();
  } else {
    did_animate =
        compositor_delegate_.GetImplDeprecated().ScrollAnimationCreate(
            *scroll_node, delta, base::TimeDelta());
  }
  DCHECK(!IsAnimatingForSnap());
  if (did_animate) {
    // The snap target will be set when the animation is completed.
    scroll_animating_snap_target_ids_ = snap_target_ids;
  } else if (data.SetTargetSnapAreaElementIds(snap_target_ids)) {
    updated_snapped_elements_.insert(scroll_node->element_id);
    SetNeedsCommit();
  }
  return did_animate;
}

bool ThreadedInputHandler::IsAnimatingForSnap() const {
  return scroll_animating_snap_target_ids_ != TargetSnapAreaElementIds();
}

gfx::ScrollOffset ThreadedInputHandler::GetVisualScrollOffset(
    const ScrollNode& scroll_node) const {
  if (scroll_node.scrolls_outer_viewport)
    return GetViewport().TotalScrollOffset();
  return GetScrollTree().current_scroll_offset(scroll_node.element_id);
}

void ThreadedInputHandler::ClearCurrentlyScrollingNode() {
  TRACE_EVENT0("cc", "ThreadedInputHandler::ClearCurrentlyScrollingNode");
  ActiveTree().ClearCurrentlyScrollingNode();
  accumulated_root_overscroll_ = gfx::Vector2dF();
  did_scroll_x_for_scroll_gesture_ = false;
  did_scroll_y_for_scroll_gesture_ = false;
  scroll_animating_snap_target_ids_ = TargetSnapAreaElementIds();
  latched_scroll_type_.reset();
  last_scroll_update_state_.reset();
  last_scroll_begin_state_.reset();
  compositor_delegate_.DidEndScroll();
}

bool ThreadedInputHandler::ScrollAnimationUpdateTarget(
    const ScrollNode& scroll_node,
    const gfx::Vector2dF& scroll_delta,
    base::TimeDelta delayed_by) {
  // TODO(bokan): Remove |scroll_node| as a parameter and just use the value
  // coming from |mutator_host|.
  DCHECK_EQ(scroll_node.element_id, compositor_delegate_.GetImplDeprecated()
                                        .mutator_host()
                                        ->ImplOnlyScrollAnimatingElement());

  float scale_factor = compositor_delegate_.PageScaleFactor();
  gfx::Vector2dF adjusted_delta =
      gfx::ScaleVector2d(scroll_delta, 1.f / scale_factor);
  adjusted_delta = UserScrollableDelta(scroll_node, adjusted_delta);

  bool animation_updated =
      compositor_delegate_.GetImplDeprecated()
          .mutator_host()
          ->ImplOnlyScrollAnimationUpdateTarget(
              adjusted_delta, GetScrollTree().MaxScrollOffset(scroll_node.id),
              compositor_delegate_.GetImplDeprecated()
                  .CurrentBeginFrameArgs()
                  .frame_time,
              delayed_by);
  if (animation_updated) {
    compositor_delegate_.DidUpdateScrollAnimationCurve();

    // The animation is no longer targeting a snap position. By clearing the
    // target, this will ensure that we attempt to resnap at the end of this
    // animation.
    scroll_animating_snap_target_ids_ = TargetSnapAreaElementIds();
  }

  return animation_updated;
}

void ThreadedInputHandler::UpdateScrollSourceInfo(
    const ScrollState& scroll_state,
    ui::ScrollInputType type) {
  if (type == ui::ScrollInputType::kWheel &&
      scroll_state.delta_granularity() ==
          ui::ScrollGranularity::kScrollByPrecisePixel) {
    has_scrolled_by_precisiontouchpad_ = true;
  } else if (type == ui::ScrollInputType::kWheel) {
    has_scrolled_by_wheel_ = true;
  } else if (type == ui::ScrollInputType::kTouchscreen) {
    has_scrolled_by_touch_ = true;
  }
}

// Return true if scrollable node for 'ancestor' is the same as 'child' or an
// ancestor along the scroll tree.
bool ThreadedInputHandler::IsScrolledBy(LayerImpl* child,
                                        ScrollNode* ancestor) {
  DCHECK(ancestor && ancestor->scrollable);
  if (!child)
    return false;
  DCHECK_EQ(child->layer_tree_impl(), &ActiveTree());
  ScrollTree& scroll_tree = GetScrollTree();
  for (ScrollNode* scroll_node = scroll_tree.Node(child->scroll_tree_index());
       scroll_node; scroll_node = scroll_tree.parent(scroll_node)) {
    if (scroll_node->id == ancestor->id)
      return true;
  }
  return false;
}

gfx::Vector2dF ThreadedInputHandler::UserScrollableDelta(
    const ScrollNode& node,
    const gfx::Vector2dF& delta) const {
  gfx::Vector2dF adjusted_delta = delta;
  if (!node.user_scrollable_horizontal)
    adjusted_delta.set_x(0);
  if (!node.user_scrollable_vertical)
    adjusted_delta.set_y(0);

  return adjusted_delta;
}

}  // namespace cc
