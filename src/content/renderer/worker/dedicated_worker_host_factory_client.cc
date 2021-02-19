// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/renderer/worker/dedicated_worker_host_factory_client.h"

#include <utility>
#include "content/renderer/loader/child_url_loader_factory_bundle.h"
#include "content/renderer/loader/resource_dispatcher.h"
#include "content/renderer/loader/web_worker_fetch_context_impl.h"
#include "content/renderer/render_thread_impl.h"
#include "content/renderer/service_worker/service_worker_provider_context.h"
#include "content/renderer/worker/fetch_client_settings_object_helpers.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/loader/worker_main_script_load_parameters.h"
#include "third_party/blink/public/common/tokens/tokens.h"
#include "third_party/blink/public/common/tokens/tokens_mojom_traits.h"
#include "third_party/blink/public/mojom/blob/blob_url_store.mojom.h"
#include "third_party/blink/public/mojom/loader/fetch_client_settings_object.mojom.h"
#include "third_party/blink/public/mojom/service_worker/controller_service_worker.mojom.h"
#include "third_party/blink/public/mojom/service_worker/service_worker_provider.mojom.h"
#include "third_party/blink/public/mojom/tokens/tokens.mojom.h"
#include "third_party/blink/public/mojom/worker/worker_main_script_load_params.mojom.h"
#include "third_party/blink/public/platform/web_dedicated_worker.h"
#include "third_party/blink/public/platform/web_url.h"

namespace content {

DedicatedWorkerHostFactoryClient::DedicatedWorkerHostFactoryClient(
    blink::WebDedicatedWorker* worker,
    const blink::BrowserInterfaceBrokerProxy& interface_broker)
    : worker_(worker) {
  interface_broker.GetInterface(factory_.BindNewPipeAndPassReceiver());
}

DedicatedWorkerHostFactoryClient::~DedicatedWorkerHostFactoryClient() = default;

void DedicatedWorkerHostFactoryClient::CreateWorkerHostDeprecated(
    const blink::DedicatedWorkerToken& dedicated_worker_token,
    base::OnceCallback<void(const network::CrossOriginEmbedderPolicy&)>
        callback) {
  DCHECK(!base::FeatureList::IsEnabled(blink::features::kPlzDedicatedWorker));
  mojo::PendingRemote<blink::mojom::BrowserInterfaceBroker>
      browser_interface_broker;
  factory_->CreateWorkerHost(
      dedicated_worker_token,
      browser_interface_broker.InitWithNewPipeAndPassReceiver(),
      std::move(callback));
  OnWorkerHostCreated(std::move(browser_interface_broker));
}

void DedicatedWorkerHostFactoryClient::CreateWorkerHost(
    const blink::DedicatedWorkerToken& dedicated_worker_token,
    const blink::WebURL& script_url,
    network::mojom::CredentialsMode credentials_mode,
    const blink::WebFetchClientSettingsObject& fetch_client_settings_object,
    blink::CrossVariantMojoRemote<blink::mojom::BlobURLTokenInterfaceBase>
        blob_url_token) {
  DCHECK(base::FeatureList::IsEnabled(blink::features::kPlzDedicatedWorker));
  factory_->CreateWorkerHostAndStartScriptLoad(
      dedicated_worker_token, script_url, credentials_mode,
      FetchClientSettingsObjectFromWebToMojom(fetch_client_settings_object),
      std::move(blob_url_token), receiver_.BindNewPipeAndPassRemote());
}

scoped_refptr<blink::WebWorkerFetchContext>
DedicatedWorkerHostFactoryClient::CloneWorkerFetchContext(
    blink::WebWorkerFetchContext* web_worker_fetch_context,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
  scoped_refptr<WebWorkerFetchContextImpl> worker_fetch_context;
  if (base::FeatureList::IsEnabled(blink::features::kPlzDedicatedWorker)) {
    worker_fetch_context =
        static_cast<WebWorkerFetchContextImpl*>(web_worker_fetch_context)
            ->CloneForNestedWorker(
                service_worker_provider_context_.get(),
                subresource_loader_factory_bundle_->Clone(),
                subresource_loader_factory_bundle_
                    ->CloneWithoutAppCacheFactory(),
                std::move(pending_subresource_loader_updater_),
                std::move(task_runner));
  } else {
    worker_fetch_context =
        static_cast<WebWorkerFetchContextImpl*>(web_worker_fetch_context)
            ->CloneForNestedWorkerDeprecated(std::move(task_runner));
  }
  return worker_fetch_context;
}

scoped_refptr<WebWorkerFetchContextImpl>
DedicatedWorkerHostFactoryClient::CreateWorkerFetchContext(
    blink::mojom::RendererPreferences renderer_preference,
    mojo::PendingReceiver<blink::mojom::RendererPreferenceWatcher>
        watcher_receiver,
    mojo::PendingRemote<blink::mojom::ResourceLoadInfoNotifier>
        pending_resource_load_info_notifier) {
  DCHECK(base::FeatureList::IsEnabled(blink::features::kPlzDedicatedWorker));
  DCHECK(subresource_loader_factory_bundle_);
  scoped_refptr<WebWorkerFetchContextImpl> worker_fetch_context =
      WebWorkerFetchContextImpl::Create(
          service_worker_provider_context_.get(),
          std::move(renderer_preference), std::move(watcher_receiver),
          subresource_loader_factory_bundle_->Clone(),
          subresource_loader_factory_bundle_->CloneWithoutAppCacheFactory(),
          std::move(pending_subresource_loader_updater_),
          RenderThreadImpl::current()
              ->resource_dispatcher()
              ->cors_exempt_header_list(),
          std::move(pending_resource_load_info_notifier));
  return worker_fetch_context;
}

void DedicatedWorkerHostFactoryClient::OnWorkerHostCreated(
    mojo::PendingRemote<blink::mojom::BrowserInterfaceBroker>
        browser_interface_broker) {
  worker_->OnWorkerHostCreated(std::move(browser_interface_broker));
}

void DedicatedWorkerHostFactoryClient::OnScriptLoadStarted(
    blink::mojom::ServiceWorkerContainerInfoForClientPtr
        service_worker_container_info,
    blink::mojom::WorkerMainScriptLoadParamsPtr main_script_load_params,
    std::unique_ptr<blink::PendingURLLoaderFactoryBundle>
        pending_subresource_loader_factory_bundle,
    mojo::PendingReceiver<blink::mojom::SubresourceLoaderUpdater>
        subresource_loader_updater,
    blink::mojom::ControllerServiceWorkerInfoPtr controller_info) {
  DCHECK(base::FeatureList::IsEnabled(blink::features::kPlzDedicatedWorker));
  DCHECK(main_script_load_params);
  DCHECK(pending_subresource_loader_factory_bundle);

  // Initialize the loader factory bundle passed by the browser process.
  DCHECK(!subresource_loader_factory_bundle_);
  subresource_loader_factory_bundle_ =
      base::MakeRefCounted<ChildURLLoaderFactoryBundle>(
          std::make_unique<ChildPendingURLLoaderFactoryBundle>(
              std::move(pending_subresource_loader_factory_bundle)));

  DCHECK(!pending_subresource_loader_updater_);
  pending_subresource_loader_updater_ = std::move(subresource_loader_updater);

  DCHECK(!service_worker_provider_context_);
  if (service_worker_container_info) {
    service_worker_provider_context_ =
        base::MakeRefCounted<ServiceWorkerProviderContext>(
            blink::mojom::ServiceWorkerContainerType::kForDedicatedWorker,
            std::move(service_worker_container_info->client_receiver),
            std::move(service_worker_container_info->host_remote),
            std::move(controller_info), subresource_loader_factory_bundle_);
  }

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
  worker_->OnScriptLoadStarted(std::move(worker_main_script_load_params));
}

void DedicatedWorkerHostFactoryClient::OnScriptLoadStartFailed() {
  DCHECK(base::FeatureList::IsEnabled(blink::features::kPlzDedicatedWorker));
  worker_->OnScriptLoadStartFailed();
  // |this| may be destroyed at this point.
}

}  // namespace content
