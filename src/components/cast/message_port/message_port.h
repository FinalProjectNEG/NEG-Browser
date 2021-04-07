// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_CAST_MESSAGE_PORT_MESSAGE_PORT_H_
#define COMPONENTS_CAST_MESSAGE_PORT_MESSAGE_PORT_H_

#include <memory>
#include <vector>

#include "base/strings/string_piece.h"

namespace cast_api_bindings {

// HTML5 MessagePort abstraction; allows usage of the platform MessagePort type
// without exposing details of the message format, paired port creation, or
// transfer of ports.
class MessagePort {
 public:
  // Implemented by receivers of messages from the MessagePort class.
  class Receiver {
   public:
    virtual ~Receiver();

    // Receives a |message| and ownership of |ports|.
    virtual bool OnMessage(base::StringPiece message,
                           std::vector<std::unique_ptr<MessagePort>> ports) = 0;

    // Receives an error.
    virtual void OnPipeError() = 0;
  };

  virtual ~MessagePort();

  // Creates a pair of message ports. Clients must respect |client| and
  // |server| semantics because they matter for some implementations.
  static void CreatePair(std::unique_ptr<MessagePort>* client,
                         std::unique_ptr<MessagePort>* server);

  // Sends a |message| from the port.
  virtual bool PostMessage(base::StringPiece message) = 0;

  // Sends a |message| from the port along with transferable |ports|.
  virtual bool PostMessageWithTransferables(
      base::StringPiece message,
      std::vector<std::unique_ptr<MessagePort>> ports) = 0;

  // Sets the |receiver| for messages arriving to this port. May only be set
  // once.
  virtual void SetReceiver(
      cast_api_bindings::MessagePort::Receiver* receiver) = 0;

  // Closes the underlying port.
  virtual void Close() = 0;

  // Whether a message can be posted; may be used to check the state of the port
  // without posting a message.
  virtual bool CanPostMessage() const = 0;
};

}  // namespace cast_api_bindings

#endif  // COMPONENTS_CAST_MESSAGE_PORT_MESSAGE_PORT_H_
