// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_RENDERER_HOST_INPUT_WEB_INPUT_EVENT_BUILDERS_MAC_H_
#define CONTENT_BROWSER_RENDERER_HOST_INPUT_WEB_INPUT_EVENT_BUILDERS_MAC_H_

#include "content/common/content_export.h"
#include "third_party/blink/public/common/input/web_gesture_event.h"
#include "third_party/blink/public/common/input/web_input_event.h"
#include "third_party/blink/public/common/input/web_keyboard_event.h"
#include "third_party/blink/public/common/input/web_mouse_wheel_event.h"
#include "third_party/blink/public/common/input/web_touch_event.h"

@class NSEvent;
@class NSView;

namespace content {

class CONTENT_EXPORT WebKeyboardEventBuilder {
 public:
  // TODO(bokan): Temporarily added the |record_debug_uma| param to help debug
  // https://crbug.com/1039833. This parameter controls whether
  // Event.Latency.OS_NO_VALIDATION metrics are collected for the key event.
  // The purpose is to limit this to only those events that are being handled
  // synchronously from the OS message loop since we can reinject the same
  // NSEvent back into the app multiple times; we want to record this stat only
  // the first time the event was received.
  static blink::WebKeyboardEvent Build(NSEvent* event,
                                       bool record_debug_uma = false);
};

class CONTENT_EXPORT WebMouseEventBuilder {
 public:
  static blink::WebMouseEvent Build(
      NSEvent* event,
      NSView* view,
      blink::WebPointerProperties::PointerType pointerType =
          blink::WebPointerProperties::PointerType::kMouse,
      bool unacceleratedMovement = false);
};

class CONTENT_EXPORT WebMouseWheelEventBuilder {
 public:
  static blink::WebMouseWheelEvent Build(NSEvent* event,
                                         NSView* view);
};

class CONTENT_EXPORT WebGestureEventBuilder {
 public:
  static blink::WebGestureEvent Build(NSEvent*, NSView*);
};

class CONTENT_EXPORT WebTouchEventBuilder {
 public:
  static blink::WebTouchEvent Build(NSEvent* event, NSView* view);
};

}  // namespace content

#endif  // CONTENT_BROWSER_RENDERER_HOST_INPUT_WEB_INPUT_EVENT_BUILDERS_MAC_H_
