// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/arc/test/arc_payment_app_bridge_test_support.h"

#include "components/arc/session/arc_bridge_service.h"

namespace arc {

ArcPaymentAppBridgeTestSupport::MockPaymentAppInstance::
    MockPaymentAppInstance() = default;

ArcPaymentAppBridgeTestSupport::MockPaymentAppInstance::
    ~MockPaymentAppInstance() = default;

ArcPaymentAppBridgeTestSupport::ScopedSetInstance::ScopedSetInstance(
    ArcServiceManager* manager,
    mojom::PaymentAppInstance* instance)
    : manager_(manager), instance_(instance) {
  manager_->arc_bridge_service()->payment_app()->SetInstance(instance_);
}

ArcPaymentAppBridgeTestSupport::ScopedSetInstance::~ScopedSetInstance() {
  manager_->arc_bridge_service()->payment_app()->CloseInstance(instance_);
}

ArcPaymentAppBridgeTestSupport::ArcPaymentAppBridgeTestSupport() = default;

ArcPaymentAppBridgeTestSupport::~ArcPaymentAppBridgeTestSupport() = default;

std::unique_ptr<ArcPaymentAppBridgeTestSupport::ScopedSetInstance>
ArcPaymentAppBridgeTestSupport::CreateScopedSetInstance() {
  return std::make_unique<ScopedSetInstance>(manager(), instance());
}

}  // namespace arc
