// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/renderer/worker/shared_worker_factory_impl.h"

#include "base/memory/ptr_util.h"
#include "content/renderer/loader/resource_dispatcher.h"
#include "content/renderer/render_thread_impl.h"
#include "content/renderer/worker/embedded_shared_worker_stub.h"
#include "mojo/public/cpp/bindings/self_owned_receiver.h"
#include "third_party/blink/public/common/loader/url_loader_factory_bundle.h"
#include "third_party/blink/public/mojom/service_worker/controller_service_worker.mojom.h"

namespace content {

// static
void SharedWorkerFactoryImpl::Create(
    mojo::PendingReceiver<blink::mojom::SharedWorkerFactory> receiver) {
  mojo::MakeSelfOwnedReceiver<blink::mojom::SharedWorkerFactory>(
      base::WrapUnique(new SharedWorkerFactoryImpl()), std::move(receiver));
}

SharedWorkerFactoryImpl::SharedWorkerFactoryImpl() {}

void SharedWorkerFactoryImpl::CreateSharedWorker(
    blink::mojom::SharedWorkerInfoPtr info,
    const blink::SharedWorkerToken& token,
    const url::Origin& constructor_origin,
    const std::string& user_agent,
    const blink::UserAgentMetadata& ua_metadata,
    bool pause_on_start,
    const base::UnguessableToken& devtools_worker_token,
    blink::mojom::RendererPreferencesPtr renderer_preferences,
    mojo::PendingReceiver<blink::mojom::RendererPreferenceWatcher>
        preference_watcher_receiver,
    mojo::PendingRemote<blink::mojom::WorkerContentSettingsProxy>
        content_settings,
    blink::mojom::ServiceWorkerContainerInfoForClientPtr
        service_worker_container_info,
    const base::Optional<base::UnguessableToken>& appcache_host_id,
    blink::mojom::WorkerMainScriptLoadParamsPtr main_script_load_params,
    std::unique_ptr<blink::PendingURLLoaderFactoryBundle>
        subresource_loader_factories,
    blink::mojom::ControllerServiceWorkerInfoPtr controller_info,
    mojo::PendingRemote<blink::mojom::SharedWorkerHost> host,
    mojo::PendingReceiver<blink::mojom::SharedWorker> receiver,
    mojo::PendingRemote<blink::mojom::BrowserInterfaceBroker>
        browser_interface_broker,
    ukm::SourceId ukm_source_id) {
  // Bound to the lifetime of the underlying blink::WebSharedWorker instance.
  new EmbeddedSharedWorkerStub(
      std::move(info), token, constructor_origin, user_agent, ua_metadata,
      pause_on_start, devtools_worker_token, *renderer_preferences,
      std::move(preference_watcher_receiver), std::move(content_settings),
      std::move(service_worker_container_info),
      appcache_host_id.value_or(base::UnguessableToken()),
      std::move(main_script_load_params),
      std::move(subresource_loader_factories), std::move(controller_info),
      std::move(host), std::move(receiver), std::move(browser_interface_broker),
      ukm_source_id,
      RenderThreadImpl::current()
          ->resource_dispatcher()
          ->cors_exempt_header_list());
}

}  // namespace content
