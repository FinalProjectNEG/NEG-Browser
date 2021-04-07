// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_CHROMEOS_CHROMEBOX_FOR_MEETINGS_FAKE_SERVICE_CONTEXT_H_
#define CHROME_BROWSER_CHROMEOS_CHROMEBOX_FOR_MEETINGS_FAKE_SERVICE_CONTEXT_H_

#include "base/bind.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/bindings/remote.h"

#include "chromeos/services/chromebox_for_meetings/public/mojom/cfm_service_manager.mojom.h"

namespace chromeos {
namespace cfm {

class FakeCfmServiceContext : public mojom::CfmServiceContext {
 public:
  using FakeProvideAdaptorCallback = base::OnceCallback<void(
      const std::string& interface_name,
      mojo::PendingRemote<mojom::CfmServiceAdaptor> adaptor_remote,
      ProvideAdaptorCallback callback)>;

  using FakeBindRegistryCallback = base::OnceCallback<void(
      const std::string& interface_name,
      mojo::PendingReceiver<mojom::CfmServiceRegistry> broker_receiver,
      BindRegistryCallback callback)>;

  FakeCfmServiceContext();
  FakeCfmServiceContext(const FakeCfmServiceContext&) = delete;
  FakeCfmServiceContext& operator=(const FakeCfmServiceContext&) = delete;
  ~FakeCfmServiceContext() override;

  void ProvideAdaptor(
      const std::string& interface_name,
      mojo::PendingRemote<mojom::CfmServiceAdaptor> adaptor_remote,
      ProvideAdaptorCallback callback) override;

  void BindRegistry(
      const std::string& interface_name,
      mojo::PendingReceiver<mojom::CfmServiceRegistry> broker_receiver,
      BindRegistryCallback callback) override;

  void SetFakeProvideAdaptorCallback(FakeProvideAdaptorCallback callback);

  void SetFakeBindRegistryCallback(FakeBindRegistryCallback callback);

 private:
  FakeProvideAdaptorCallback provide_adaptor_callback_;
  FakeBindRegistryCallback bind_registry_callback_;
};

}  // namespace cfm
}  // namespace chromeos

#endif  // CHROME_BROWSER_CHROMEOS_CHROMEBOX_FOR_MEETINGS_FAKE_SERVICE_CONTEXT_H_
