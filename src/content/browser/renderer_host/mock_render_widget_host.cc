// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/renderer_host/mock_render_widget_host.h"

#include "components/viz/test/mock_compositor_frame_sink_client.h"
#include "content/browser/renderer_host/frame_token_message_queue.h"

namespace content {

MockRenderWidgetHost::~MockRenderWidgetHost() {}

void MockRenderWidgetHost::OnTouchEventAck(
    const TouchEventWithLatencyInfo& event,
    blink::mojom::InputEventResultSource ack_source,
    blink::mojom::InputEventResultState ack_result) {
  // Sniff touch acks.
  acked_touch_event_type_ = event.event.GetType();
  RenderWidgetHostImpl::OnTouchEventAck(event, ack_source, ack_result);
}

void MockRenderWidgetHost::DisableGestureDebounce() {
  input_router_.reset(new InputRouterImpl(this, this, fling_scheduler_.get(),
                                          InputRouter::Config()));
}

void MockRenderWidgetHost::ExpectForceEnableZoom(bool enable) {
  EXPECT_EQ(enable, force_enable_zoom_);

  InputRouterImpl* input_router =
      static_cast<InputRouterImpl*>(input_router_.get());
  EXPECT_EQ(enable, input_router->touch_action_filter_.force_enable_zoom_);
}

void MockRenderWidgetHost::SetupForInputRouterTest() {
  input_router_.reset(new MockInputRouter(this));
}

// static
MockRenderWidgetHost* MockRenderWidgetHost::Create(
    RenderWidgetHostDelegate* delegate,
    AgentSchedulingGroupHost& agent_scheduling_group,
    int32_t routing_id) {
  mojo::AssociatedRemote<blink::mojom::Widget> blink_widget;
  auto blink_widget_receiver =
      blink_widget.BindNewEndpointAndPassDedicatedReceiver();
  return new MockRenderWidgetHost(delegate, agent_scheduling_group, routing_id,
                                  blink_widget.Unbind());
}

MockRenderWidgetHost* MockRenderWidgetHost::Create(
    RenderWidgetHostDelegate* delegate,
    AgentSchedulingGroupHost& agent_scheduling_group,
    int32_t routing_id,
    mojo::PendingAssociatedRemote<blink::mojom::Widget> pending_blink_widget) {
  DCHECK(pending_blink_widget);
  return new MockRenderWidgetHost(delegate, agent_scheduling_group, routing_id,
                                  std::move(pending_blink_widget));
}

blink::mojom::WidgetInputHandler*
MockRenderWidgetHost::GetWidgetInputHandler() {
  return &mock_widget_input_handler_;
}

void MockRenderWidgetHost::NotifyNewContentRenderingTimeoutForTesting() {
  new_content_rendering_timeout_fired_ = true;
}

MockRenderWidgetHost::MockRenderWidgetHost(
    RenderWidgetHostDelegate* delegate,
    AgentSchedulingGroupHost& agent_scheduling_group,
    int routing_id,
    mojo::PendingAssociatedRemote<blink::mojom::Widget> pending_blink_widget)
    : RenderWidgetHostImpl(delegate,
                           agent_scheduling_group,
                           routing_id,
                           /*hidden=*/false,
                           std::make_unique<FrameTokenMessageQueue>()),
      new_content_rendering_timeout_fired_(false),
      fling_scheduler_(std::make_unique<FlingScheduler>(this)) {
  acked_touch_event_type_ = blink::WebInputEvent::Type::kUndefined;
  mojo::AssociatedRemote<blink::mojom::WidgetHost> blink_widget_host;
  BindWidgetInterfaces(
      blink_widget_host.BindNewEndpointAndPassDedicatedReceiver(),
      std::move(pending_blink_widget));
}

}  // namespace content
