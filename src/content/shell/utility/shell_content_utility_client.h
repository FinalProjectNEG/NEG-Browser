// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_SHELL_UTILITY_SHELL_CONTENT_UTILITY_CLIENT_H_
#define CONTENT_SHELL_UTILITY_SHELL_CONTENT_UTILITY_CLIENT_H_

#include "base/macros.h"
#include "content/public/test/audio_service_test_helper.h"
#include "content/public/test/network_service_test_helper.h"
#include "content/public/utility/content_utility_client.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"

namespace content {

class ShellContentUtilityClient : public ContentUtilityClient {
 public:
  explicit ShellContentUtilityClient(bool is_browsertest = false);
  ~ShellContentUtilityClient() override;

  // ContentUtilityClient:
  void ExposeInterfacesToBrowser(mojo::BinderMap* binders) override;
  bool HandleServiceRequest(
      const std::string& service_name,
      mojo::PendingReceiver<service_manager::mojom::Service> receiver) override;
  mojo::ServiceFactory* GetIOThreadServiceFactory() override;
  void RegisterNetworkBinders(
      service_manager::BinderRegistry* registry) override;

 private:
  std::unique_ptr<NetworkServiceTestHelper> network_service_test_helper_;
  std::unique_ptr<AudioServiceTestHelper> audio_service_test_helper_;
  bool register_sandbox_status_helper_ = false;

  DISALLOW_COPY_AND_ASSIGN(ShellContentUtilityClient);
};

}  // namespace content

#endif  // CONTENT_SHELL_UTILITY_SHELL_CONTENT_UTILITY_CLIENT_H_
