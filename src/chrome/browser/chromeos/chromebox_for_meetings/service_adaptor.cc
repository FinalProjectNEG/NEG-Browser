// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/chromeos/chromebox_for_meetings/service_adaptor.h"

#include "chromeos/services/chromebox_for_meetings/public/cpp/service_connection.h"

namespace chromeos {
namespace cfm {

ServiceAdaptor::ServiceAdaptor(std::string interface_name, Delegate* delegate)
    : interface_name_(std::move(interface_name)), delegate_(delegate) {
  DCHECK(delegate_);
}

ServiceAdaptor::~ServiceAdaptor() = default;

mojom::CfmServiceContext* ServiceAdaptor::GetContext() {
  if (!context_.is_bound()) {
    ServiceConnection::GetInstance()->BindServiceContext(
        context_.BindNewPipeAndPassReceiver());
    context_.reset_on_disconnect();
  }

  return context_.get();
}

void ServiceAdaptor::BindServiceAdaptor() {
  if (adaptor_.is_bound()) {
    return;
  }

  GetContext()->ProvideAdaptor(interface_name_,
                               adaptor_.BindNewPipeAndPassRemote(),
                               base::BindOnce(&ServiceAdaptor::OnAdaptorConnect,
                                              weak_ptr_factory_.GetWeakPtr()));

  adaptor_.set_disconnect_handler(base::BindOnce(
      &ServiceAdaptor::OnAdaptorDisconnect, base::Unretained(this)));
}

void ServiceAdaptor::BindService(mojo::ScopedMessagePipeHandle receiver_pipe) {
  delegate_->BindService(std::move(receiver_pipe));
}

void ServiceAdaptor::OnAdaptorConnect(bool success) {
  DLOG_IF(WARNING, !success) << "Failed Registration for " << interface_name_;
  if (!success) {
    // If the connection to |CfmServiceContext| is unsuccessful reset the
    // adaptor to allow for future attempts.
    adaptor_.reset();
  }

  delegate_->OnAdaptorConnect(success);
}

void ServiceAdaptor::OnAdaptorDisconnect() {
  adaptor_.reset();
  delegate_->OnAdaptorDisconnect();
}

}  // namespace cfm
}  // namespace chromeos
