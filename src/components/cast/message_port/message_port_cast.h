// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_CAST_MESSAGE_PORT_MESSAGE_PORT_CAST_H_
#define COMPONENTS_CAST_MESSAGE_PORT_MESSAGE_PORT_CAST_H_

#include "components/cast/message_port/message_port.h"
#include "third_party/blink/public/common/messaging/web_message_port.h"

namespace cast_api_bindings {

// Abstraction of HTML MessagePortCast away from blink::WebMessagePort
// Represents one end of a message channel.
class MessagePortCast : public cast_api_bindings::MessagePort,
                        public blink::WebMessagePort::MessageReceiver {
 public:
  explicit MessagePortCast(blink::WebMessagePort&& port);
  ~MessagePortCast() override;

  MessagePortCast(const MessagePortCast&) = delete;
  MessagePortCast& operator=(const MessagePortCast&) = delete;

  static std::unique_ptr<MessagePort> Create(blink::WebMessagePort&& port);

  // Gets the implementation of |port| for callers who know its platform type.
  static MessagePortCast* FromMessagePort(MessagePort* port);

  // Retrieves the platform-specific port and invalidates this object.
  blink::WebMessagePort TakePort();

 private:
  // cast_api_bindings::MessagePort implementation
  bool PostMessage(base::StringPiece message) final;
  bool PostMessageWithTransferables(
      base::StringPiece message,
      std::vector<std::unique_ptr<MessagePort>> ports) final;
  void SetReceiver(cast_api_bindings::MessagePort::Receiver* receiver) final;
  void Close() final;
  bool CanPostMessage() const final;

  // blink::WebMessagePort::MessageReceiver implementation
  bool OnMessage(blink::WebMessagePort::Message message) final;
  void OnPipeError() final;

  cast_api_bindings::MessagePort::Receiver* receiver_;
  blink::WebMessagePort port_;
};

}  // namespace cast_api_bindings

#endif  // COMPONENTS_CAST_MESSAGE_PORT_MESSAGE_PORT_CAST_H_
