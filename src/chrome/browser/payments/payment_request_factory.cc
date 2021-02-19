// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/payments/payment_request_factory.h"

#include <memory>
#include <utility>

#include "base/no_destructor.h"
#include "chrome/browser/payments/chrome_payment_request_delegate.h"
#include "components/payments/content/payment_request_web_contents_manager.h"
#include "content/public/browser/render_frame_host.h"
#include "content/public/browser/web_contents.h"
#include "mojo/public/cpp/bindings/message.h"
#include "third_party/blink/public/mojom/feature_policy/feature_policy_feature.mojom-shared.h"

namespace payments {

namespace {

using PaymentRequestFactoryCallback = base::RepeatingCallback<void(
    mojo::PendingReceiver<mojom::PaymentRequest> receiver,
    content::RenderFrameHost* render_frame_host)>;

PaymentRequestFactoryCallback& GetTestingFactoryCallback() {
  static base::NoDestructor<PaymentRequestFactoryCallback> callback;
  return *callback;
}

}  // namespace

void CreatePaymentRequest(
    content::RenderFrameHost* render_frame_host,
    mojo::PendingReceiver<mojom::PaymentRequest> receiver) {
  if (!render_frame_host->IsCurrent()) {
    // This happens when the page has navigated away, which would cause the
    // blink PaymentRequest to be released shortly, or when the iframe is being
    // removed from the page, which is not a use case that we support.
    // Abandoning the `receiver` will close the mojo connection, so blink
    // PaymentRequest will receive a connection error and will clean up itself.
    return;
  }

  if (!render_frame_host->IsFeatureEnabled(
          blink::mojom::FeaturePolicyFeature::kPayment)) {
    mojo::ReportBadMessage("Feature policy blocks Payment");
    return;
  }

  if (GetTestingFactoryCallback()) {
    return GetTestingFactoryCallback().Run(std::move(receiver),
                                           render_frame_host);
  }

  PaymentRequestWebContentsManager::GetOrCreateForWebContents(
      content::WebContents::FromRenderFrameHost(render_frame_host))
      ->CreatePaymentRequest(
          render_frame_host,
          std::make_unique<ChromePaymentRequestDelegate>(render_frame_host),
          std::move(receiver),
          /*observer_for_testing=*/nullptr);
}

void SetPaymentRequestFactoryForTesting(
    PaymentRequestFactoryCallback factory_callback) {
  GetTestingFactoryCallback() = std::move(factory_callback);
}

}  // namespace payments
