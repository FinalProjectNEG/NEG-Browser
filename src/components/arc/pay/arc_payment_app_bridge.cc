// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/arc/pay/arc_payment_app_bridge.h"

#include <utility>

#include "base/bind.h"
#include "base/memory/singleton.h"
#include "base/no_destructor.h"
#include "components/arc/arc_browser_context_keyed_service_factory_base.h"
#include "components/arc/session/arc_bridge_service.h"

namespace arc {
namespace {

static constexpr char kUnableToConnectErrorMessage[] =
    "Unable to invoke Android apps.";

class ArcPaymentAppBridgeFactory
    : public internal::ArcBrowserContextKeyedServiceFactoryBase<
          ArcPaymentAppBridge,
          ArcPaymentAppBridgeFactory> {
 public:
  // Factory name used by ArcBrowserContextKeyedServiceFactoryBase.
  static constexpr const char* kName = "ArcPaymentAppBridgeFactory";

  static ArcPaymentAppBridgeFactory* GetInstance() {
    static base::NoDestructor<ArcPaymentAppBridgeFactory> factory;
    return factory.get();
  }

  ArcPaymentAppBridgeFactory() = default;
  ~ArcPaymentAppBridgeFactory() override = default;

 private:
  friend base::DefaultSingletonTraits<ArcPaymentAppBridgeFactory>;
};

}  // namespace

// static
ArcPaymentAppBridge* ArcPaymentAppBridge::GetForBrowserContext(
    content::BrowserContext* context) {
  return ArcPaymentAppBridgeFactory::GetForBrowserContext(context);
}

// static
ArcPaymentAppBridge* ArcPaymentAppBridge::GetForBrowserContextForTesting(
    content::BrowserContext* context) {
  return ArcPaymentAppBridgeFactory::GetForBrowserContextForTesting(context);
}

ArcPaymentAppBridge::ArcPaymentAppBridge(
    content::BrowserContext* browser_context,
    ArcBridgeService* bridge_service)
    : arc_bridge_service_(bridge_service) {}

ArcPaymentAppBridge::~ArcPaymentAppBridge() = default;

void ArcPaymentAppBridge::IsPaymentImplemented(
    const std::string& package_name,
    IsPaymentImplementedCallback callback) {
  mojom::PaymentAppInstance* payment_app = ARC_GET_INSTANCE_FOR_METHOD(
      arc_bridge_service_->payment_app(), IsPaymentImplemented);
  if (!payment_app) {
    std::move(callback).Run(mojom::IsPaymentImplementedResult::NewError(
        kUnableToConnectErrorMessage));
    return;
  }

  payment_app->IsPaymentImplemented(package_name, std::move(callback));
}

void ArcPaymentAppBridge::IsReadyToPay(mojom::PaymentParametersPtr parameters,
                                       IsReadyToPayCallback callback) {
  mojom::PaymentAppInstance* payment_app = ARC_GET_INSTANCE_FOR_METHOD(
      arc_bridge_service_->payment_app(), IsReadyToPay);
  if (!payment_app) {
    std::move(callback).Run(
        mojom::IsReadyToPayResult::NewError(kUnableToConnectErrorMessage));
    return;
  }

  payment_app->IsReadyToPay(std::move(parameters), std::move(callback));
}

void ArcPaymentAppBridge::InvokePaymentApp(
    mojom::PaymentParametersPtr parameters,
    InvokePaymentAppCallback callback) {
  mojom::PaymentAppInstance* payment_app = ARC_GET_INSTANCE_FOR_METHOD(
      arc_bridge_service_->payment_app(), InvokePaymentApp);
  if (!payment_app) {
    std::move(callback).Run(
        mojom::InvokePaymentAppResult::NewError(kUnableToConnectErrorMessage));
    return;
  }

  payment_app->InvokePaymentApp(std::move(parameters), std::move(callback));
}

}  // namespace arc
