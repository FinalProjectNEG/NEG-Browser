// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/renderer/worker/embedded_shared_worker_stub.h"

#include <stdint.h>
#include <utility>

#include "base/bind.h"
#include "base/feature_list.h"
#include "content/public/common/network_service_util.h"
#include "content/renderer/loader/child_url_loader_factory_bundle.h"
#include "content/renderer/loader/web_worker_fetch_context_impl.h"
#include "content/renderer/worker/fetch_client_settings_object_helpers.h"
#include "services/network/public/cpp/shared_url_loader_factory.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/loader/url_loader_factory_bundle.h"
#include "third_party/blink/public/common/loader/worker_main_script_load_parameters.h"
#include "third_party/blink/public/common/messaging/message_port_channel.h"
#include "third_party/blink/public/common/messaging/message_port_descriptor.h"
#include "third_party/blink/public/mojom/browser_interface_broker.mojom.h"
#include "third_party/blink/public/mojom/devtools/devtools_agent.mojom.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_object.mojom.h"
#include "third_party/blink/public/mojom/worker/worker_content_settings_proxy.mojom.h"
#include "third_party/blink/public/platform/web_fetch_client_settings_object.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/web/web_shared_worker.h"
#include "url/origin.h"

namespace content {

EmbeddedSharedWorkerStub::EmbeddedSharedWorkerStub(
    blink::mojom::SharedWorkerInfoPtr info,
    const blink::SharedWorkerToken& token,
    const url::Origin& constructor_origin,
    const std::string& user_agent,
    const blink::UserAgentMetadata& ua_metadata,
    bool pause_on_start,
    const base::UnguessableToken& devtools_worker_token,
    const blink::mojom::RendererPreferences& renderer_preferences,
    mojo::PendingReceiver<blink::mojom::RendererPreferenceWatcher>
        preference_watcher_receiver,
    mojo::PendingRemote<blink::mojom::WorkerContentSettingsProxy>
        content_settings,
    blink::mojom::ServiceWorkerContainerInfoForClientPtr
        service_worker_container_info,
    const base::UnguessableToken& appcache_host_id,
    blink::mojom::WorkerMainScriptLoadParamsPtr main_script_load_params,
    std::unique_ptr<blink::PendingURLLoaderFactoryBundle>
        pending_subresource_loader_factory_bundle,
    blink::mojom::ControllerServiceWorkerInfoPtr controller_info,
    mojo::PendingRemote<blink::mojom::SharedWorkerHost> host,
    mojo::PendingReceiver<blink::mojom::SharedWorker> receiver,
    mojo::PendingRemote<blink::mojom::BrowserInterfaceBroker>
        browser_interface_broker,
    ukm::SourceId ukm_source_id,
    const std::vector<std::string>& cors_exempt_header_list)
    : receiver_(this, std::move(receiver)) {
  DCHECK(main_script_load_params);
  DCHECK(pending_subresource_loader_factory_bundle);

  // Initialize the loading parameters for the main worker script loaded by
  // the browser process.
  auto worker_main_script_load_params =
      std::make_unique<blink::WorkerMainScriptLoadParameters>();
  worker_main_script_load_params->response_head =
      std::move(main_script_load_params->response_head);
  worker_main_script_load_params->response_body =
      std::move(main_script_load_params->response_body);
  worker_main_script_load_params->redirect_responses =
      std::move(main_script_load_params->redirect_response_heads);
  worker_main_script_load_params->redirect_infos =
      main_script_load_params->redirect_infos;
  worker_main_script_load_params->url_loader_client_endpoints =
      std::move(main_script_load_params->url_loader_client_endpoints);

  // If the network service crashes, then self-destruct so clients don't get
  // stuck with a worker with a broken loader. Self-destruction is effectively
  // the same as the worker's process crashing.
  if (IsOutOfProcessNetworkService()) {
    default_factory_disconnect_handler_holder_.Bind(std::move(
        pending_subresource_loader_factory_bundle->pending_default_factory()));
    default_factory_disconnect_handler_holder_->Clone(
        pending_subresource_loader_factory_bundle->pending_default_factory()
            .InitWithNewPipeAndPassReceiver());
    default_factory_disconnect_handler_holder_.set_disconnect_handler(
        base::BindOnce(&EmbeddedSharedWorkerStub::Terminate,
                       base::Unretained(this)));
  }

  // Initialize the subresource loader factory bundle passed by the browser
  // process.
  subresource_loader_factory_bundle_ =
      base::MakeRefCounted<ChildURLLoaderFactoryBundle>(
          std::make_unique<ChildPendingURLLoaderFactoryBundle>(
              std::move(pending_subresource_loader_factory_bundle)));

  if (service_worker_container_info) {
    service_worker_provider_context_ =
        base::MakeRefCounted<ServiceWorkerProviderContext>(
            blink::mojom::ServiceWorkerContainerType::kForDedicatedWorker,
            std::move(service_worker_container_info->client_receiver),
            std::move(service_worker_container_info->host_remote),
            std::move(controller_info), subresource_loader_factory_bundle_);
  }

  scoped_refptr<blink::WebWorkerFetchContext> worker_fetch_context =
      CreateWorkerFetchContext(info->url, std::move(renderer_preferences),
                               std::move(preference_watcher_receiver),
                               cors_exempt_header_list);

  impl_ = blink::WebSharedWorker::CreateAndStart(
      token, info->url, info->options->type, info->options->credentials,
      blink::WebString::FromUTF8(info->options->name),
      blink::WebSecurityOrigin(constructor_origin),
      blink::WebString::FromUTF8(user_agent), ua_metadata,
      blink::WebString::FromUTF8(info->content_security_policy),
      info->content_security_policy_type, info->creation_address_space,
      FetchClientSettingsObjectFromMojomToWeb(
          info->outside_fetch_client_settings_object),
      appcache_host_id, devtools_worker_token, std::move(content_settings),
      std::move(browser_interface_broker), pause_on_start,
      std::move(worker_main_script_load_params),
      std::move(worker_fetch_context), std::move(host), this, ukm_source_id);

  // If the host drops its connection, then self-destruct.
  receiver_.set_disconnect_handler(base::BindOnce(
      &EmbeddedSharedWorkerStub::Terminate, base::Unretained(this)));
}

EmbeddedSharedWorkerStub::~EmbeddedSharedWorkerStub() {
  // Destruction closes our connection to the host, triggering the host to
  // cleanup and notify clients of this worker going away.
}

void EmbeddedSharedWorkerStub::WorkerContextDestroyed() {
  delete this;
}

scoped_refptr<blink::WebWorkerFetchContext>
EmbeddedSharedWorkerStub::CreateWorkerFetchContext(
    const GURL& url,
    const blink::mojom::RendererPreferences& renderer_preferences,
    mojo::PendingReceiver<blink::mojom::RendererPreferenceWatcher>
        preference_watcher_receiver,
    const std::vector<std::string>& cors_exempt_header_list) {
  // Make the factory used for service worker network fallback (that should
  // skip AppCache if it is provided).
  std::unique_ptr<network::PendingSharedURLLoaderFactory> fallback_factory =
      subresource_loader_factory_bundle_->CloneWithoutAppCacheFactory();

  // |pending_subresource_loader_updater| and
  // |pending_resource_load_info_notifier| are not used for shared workers.
  scoped_refptr<WebWorkerFetchContextImpl> worker_fetch_context =
      WebWorkerFetchContextImpl::Create(
          service_worker_provider_context_.get(),
          std::move(renderer_preferences),
          std::move(preference_watcher_receiver),
          subresource_loader_factory_bundle_->Clone(),
          std::move(fallback_factory),
          /*pending_subresource_loader_updater=*/mojo::NullReceiver(),
          cors_exempt_header_list,
          /*pending_resource_load_info_notifier=*/mojo::NullRemote());

  // TODO(horo): To get the correct first_party_to_cookies for the shared
  // worker, we need to check the all documents bounded by the shared worker.
  // (crbug.com/723553)
  // https://tools.ietf.org/html/draft-ietf-httpbis-cookie-same-site-07#section-2.1.2
  worker_fetch_context->set_site_for_cookies(net::SiteForCookies::FromUrl(url));

  return worker_fetch_context;
}

void EmbeddedSharedWorkerStub::Connect(int connection_request_id,
                                       blink::MessagePortDescriptor port) {
  impl_->Connect(connection_request_id, std::move(port));
}

void EmbeddedSharedWorkerStub::Terminate() {
  impl_->TerminateWorkerContext();
}

}  // namespace content
