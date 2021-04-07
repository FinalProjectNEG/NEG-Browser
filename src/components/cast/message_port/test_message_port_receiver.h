// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_CAST_MESSAGE_PORT_TEST_MESSAGE_PORT_RECEIVER_H_
#define COMPONENTS_CAST_MESSAGE_PORT_TEST_MESSAGE_PORT_RECEIVER_H_

#include <memory>
#include <vector>

#include "base/callback.h"
#include "base/strings/string_piece.h"
#include "components/cast/message_port/message_port.h"

namespace cast_api_bindings {

class TestMessagePortReceiver
    : public cast_api_bindings::MessagePort::Receiver {
 public:
  TestMessagePortReceiver();
  ~TestMessagePortReceiver() override;

  TestMessagePortReceiver(const TestMessagePortReceiver&) = delete;
  TestMessagePortReceiver& operator=(const TestMessagePortReceiver&) = delete;

  // Spins a RunLoop until |buffer_| has |message_count| messages.
  bool RunUntilMessageCountEqual(size_t message_count);

  // Spins a RunLoop until the associated MessagePort is disconnected.
  void RunUntilDisconnected();

  std::vector<
      std::pair<std::string, std::vector<std::unique_ptr<MessagePort>>>>&
  buffer() {
    return buffer_;
  }

 private:
  // MessagePort::Receiver implementation.
  bool OnMessage(base::StringPiece message,
                 std::vector<std::unique_ptr<MessagePort>> ports) final;
  void OnPipeError() final;

  std::vector<std::pair<std::string, std::vector<std::unique_ptr<MessagePort>>>>
      buffer_;
  size_t message_count_target_ = 0;
  base::OnceClosure on_receive_satisfied_;
  base::OnceClosure on_disconnect_;
};

}  // namespace cast_api_bindings

#endif  // COMPONENTS_CAST_MESSAGE_PORT_TEST_MESSAGE_PORT_RECEIVER_H_
