// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_CAST_MESSAGE_PORT_MESSAGE_PORT_FUCHSIA_H_
#define COMPONENTS_CAST_MESSAGE_PORT_MESSAGE_PORT_FUCHSIA_H_

#include <fuchsia/web/cpp/fidl.h>
#include <lib/fidl/cpp/binding.h>
#include <lib/fidl/cpp/interface_handle.h>
#include <lib/fidl/cpp/interface_request.h>

#include "base/containers/circular_deque.h"
#include "components/cast/message_port/message_port.h"
#include "fuchsia/fidl/chromium/cast/cpp/fidl.h"

namespace cast_api_bindings {

// Implements the MessagePort abstraction for the FIDL interface
// fuchsia::web::WebMessagePort.
class MessagePortFuchsia : public cast_api_bindings::MessagePort {
 public:
  ~MessagePortFuchsia() override;

  MessagePortFuchsia(const MessagePortFuchsia&) = delete;
  MessagePortFuchsia& operator=(const MessagePortFuchsia&) = delete;

  static std::unique_ptr<MessagePort> Create(
      fidl::InterfaceHandle<::fuchsia::web::MessagePort> port);
  static std::unique_ptr<MessagePort> Create(
      fidl::InterfaceRequest<::fuchsia::web::MessagePort> port);

  // Gets the implementation of |port| for callers who know its platform type.
  static MessagePortFuchsia* FromMessagePort(MessagePort* port);

  // Returns the platform-specific port resources and invalidates this object.
  // The caller is responsible for choosing the take method which is appropriate
  // to the underlying FIDL resource. Attempting to take the wrong resource will
  // produce a DCHECK failure.
  virtual fidl::InterfaceHandle<::fuchsia::web::MessagePort>
  TakeClientHandle() = 0;
  virtual fidl::InterfaceRequest<::fuchsia::web::MessagePort>
  TakeServiceRequest() = 0;

 protected:
  // Represents whether a MessagePortFuchsia was created from an InterfaceHandle
  // (PortType::HANDLE) or InterfaceRequest (PortType::REQUEST)
  enum class PortType {
    HANDLE = 1,
    REQUEST = 2,
  };

  explicit MessagePortFuchsia(PortType port_type);

  // Creates a fuchsia::web::WebMessage containing |message| and transferring
  // |ports|
  static fuchsia::web::WebMessage CreateWebMessage(
      base::StringPiece message,
      std::vector<std::unique_ptr<MessagePort>> ports);

  // Delivers a message to FIDL from |message_queue_|.
  virtual void DeliverMessageToFidl() = 0;

  // Receives a |message| from FIDL into |message_queue_|. Returns a value if
  // an error occurred.
  base::Optional<fuchsia::web::FrameError> ReceiveMessageFromFidl(
      fuchsia::web::WebMessage message);

  void OnZxError(zx_status_t status);
  void ReportPipeError();

  // cast_api_bindings::MessagePort implementation
  bool PostMessage(base::StringPiece message) final;
  bool PostMessageWithTransferables(
      base::StringPiece message,
      std::vector<std::unique_ptr<MessagePort>> ports) final;

  cast_api_bindings::MessagePort::Receiver* receiver_;
  base::circular_deque<fuchsia::web::WebMessage> message_queue_;

 private:
  const PortType port_type_;
};

}  // namespace cast_api_bindings

#endif  // COMPONENTS_CAST_MESSAGE_PORT_MESSAGE_PORT_FUCHSIA_H_
