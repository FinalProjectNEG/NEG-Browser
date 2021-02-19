// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_PUBLIC_BROWSER_NETWORK_SERVICE_INSTANCE_H_
#define CONTENT_PUBLIC_BROWSER_NETWORK_SERVICE_INSTANCE_H_

#include <memory>

#include "base/callback.h"
#include "base/callback_list.h"
#include "build/build_config.h"
#include "content/common/content_export.h"
#include "services/cert_verifier/public/mojom/cert_verifier_service_factory.mojom-forward.h"
#include "services/network/public/cpp/network_connection_tracker.h"
#include "services/network/public/mojom/network_context.mojom-forward.h"

namespace base {
class SequencedTaskRunner;
}

namespace net {
class NetworkChangeNotifier;
}  // namespace net

namespace network {
class NetworkService;
namespace mojom {
class NetworkService;
}
}  // namespace network

namespace content {

// Returns a pointer to the NetworkService, creating / re-creating it as needed.
// NetworkService will be running in-process if
//   1) kNetworkService feature is disabled, or
//   2) kNetworkService and kNetworkServiceInProcess are enabled
// Otherwise it runs out of process.
// This method can only be called on the UI thread.
CONTENT_EXPORT network::mojom::NetworkService* GetNetworkService();

// Only on ChromeOS since it's only used there.
#if defined(OS_CHROMEOS)
// Returns the global NetworkChangeNotifier instance.
CONTENT_EXPORT net::NetworkChangeNotifier* GetNetworkChangeNotifier();
#endif

// Call |FlushForTesting()| on cached |mojo::Remote<NetworkService>|. For
// testing only. Must only be called on the UI thread.
CONTENT_EXPORT void FlushNetworkServiceInstanceForTesting();

// Returns a NetworkConnectionTracker that can be used to subscribe for
// network change events.
// Must only be called on the UI thread.
CONTENT_EXPORT network::NetworkConnectionTracker* GetNetworkConnectionTracker();

// Asynchronously calls the given callback with a NetworkConnectionTracker that
// can be used to subscribe to network change events.
//
// This is a helper method for classes that can't easily call
// GetNetworkConnectionTracker from the UI thread.
CONTENT_EXPORT void GetNetworkConnectionTrackerFromUIThread(
    base::OnceCallback<void(network::NetworkConnectionTracker*)> callback);

// Helper method to create a NetworkConnectionTrackerAsyncGetter.
CONTENT_EXPORT network::NetworkConnectionTrackerAsyncGetter
CreateNetworkConnectionTrackerAsyncGetter();

// Sets the NetworkConnectionTracker instance to use. For testing only.
// Must be called on the UI thread. Must be called before the first call to
// GetNetworkConnectionTracker.
CONTENT_EXPORT void SetNetworkConnectionTrackerForTesting(
    network::NetworkConnectionTracker* network_connection_tracker);

// Gets the task runner for the thread the network service will be running on
// when running in-process. Can only be called when network service is in
// process.
CONTENT_EXPORT const scoped_refptr<base::SequencedTaskRunner>&
GetNetworkTaskRunner();

// Returns a CertVerifierParams that can be placed into a new
// network::mojom::NetworkContextParams.
//
// If the CertVerifierService feature is enabled, the
// |cert_verifier_creation_params| will be used to configure a new
// CertVerifierService, and a pipe to the new CertVerifierService will be placed
// in the CertVerifierParams.
//
// Otherwise, |cert_verifier_creation_params| will just be placed directly into
// the CertVerifierParams to configure an in-network-service CertVerifier.
CONTENT_EXPORT network::mojom::CertVerifierParamsPtr GetCertVerifierParams(
    network::mojom::CertVerifierCreationParamsPtr
        cert_verifier_creation_params);

// Sets the CertVerifierServiceFactory used to instantiate
// CertVerifierServices.
CONTENT_EXPORT void SetCertVerifierServiceFactoryForTesting(
    cert_verifier::mojom::CertVerifierServiceFactory* service_factory);

}  // namespace content

#endif  // CONTENT_PUBLIC_BROWSER_NETWORK_SERVICE_INSTANCE_H_
