// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/payments/content/android_payment_app.h"

#include <utility>

#include "base/check.h"
#include "components/payments/core/method_strings.h"
#include "components/payments/core/native_error_strings.h"
#include "components/payments/core/payer_data.h"

namespace payments {

AndroidPaymentApp::AndroidPaymentApp(
    const std::set<std::string>& payment_method_names,
    std::unique_ptr<std::map<std::string, std::set<std::string>>>
        stringified_method_data,
    const GURL& top_level_origin,
    const GURL& payment_request_origin,
    const std::string& payment_request_id,
    std::unique_ptr<AndroidAppDescription> description,
    base::WeakPtr<AndroidAppCommunication> communication)
    : PaymentApp(/*icon_resource_id=*/0, PaymentApp::Type::NATIVE_MOBILE_APP),
      stringified_method_data_(std::move(stringified_method_data)),
      top_level_origin_(top_level_origin),
      payment_request_origin_(payment_request_origin),
      payment_request_id_(payment_request_id),
      description_(std::move(description)),
      communication_(communication) {
  DCHECK(!payment_method_names.empty());
  DCHECK_EQ(payment_method_names.size(), stringified_method_data_->size());
  DCHECK_EQ(*payment_method_names.begin(),
            stringified_method_data_->begin()->first);
  DCHECK(description_);
  DCHECK(!description_->package.empty());
  DCHECK_EQ(1U, description_->activities.size());
  DCHECK(!description_->activities.front()->name.empty());

  app_method_names_ = payment_method_names;
}

AndroidPaymentApp::~AndroidPaymentApp() = default;

void AndroidPaymentApp::InvokePaymentApp(Delegate* delegate) {
  // Browser is closing, so no need to invoke a callback.
  if (!communication_)
    return;

  communication_->InvokePaymentApp(
      description_->package, description_->activities.front()->name,
      *stringified_method_data_, top_level_origin_, payment_request_origin_,
      payment_request_id_,
      base::BindOnce(&AndroidPaymentApp::OnPaymentAppResponse,
                     weak_ptr_factory_.GetWeakPtr(), delegate));
}

bool AndroidPaymentApp::IsCompleteForPayment() const {
  return true;
}

uint32_t AndroidPaymentApp::GetCompletenessScore() const {
  return 0;
}

bool AndroidPaymentApp::CanPreselect() const {
  return true;
}

base::string16 AndroidPaymentApp::GetMissingInfoLabel() const {
  NOTREACHED();
  return base::string16();
}

bool AndroidPaymentApp::HasEnrolledInstrument() const {
  return true;
}

void AndroidPaymentApp::RecordUse() {
  NOTIMPLEMENTED();
}

bool AndroidPaymentApp::NeedsInstallation() const {
  return false;
}

std::string AndroidPaymentApp::GetId() const {
  return description_->package;
}

base::string16 AndroidPaymentApp::GetLabel() const {
  return base::string16();
}

base::string16 AndroidPaymentApp::GetSublabel() const {
  return base::string16();
}

const SkBitmap* AndroidPaymentApp::icon_bitmap() const {
  return nullptr;
}

bool AndroidPaymentApp::IsValidForModifier(
    const std::string& method,
    bool supported_networks_specified,
    const std::set<std::string>& supported_networks) const {
  bool is_valid = false;
  IsValidForPaymentMethodIdentifier(method, &is_valid);
  return is_valid;
}

base::WeakPtr<PaymentApp> AndroidPaymentApp::AsWeakPtr() {
  return weak_ptr_factory_.GetWeakPtr();
}

bool AndroidPaymentApp::HandlesShippingAddress() const {
  return false;
}

bool AndroidPaymentApp::HandlesPayerName() const {
  return false;
}

bool AndroidPaymentApp::HandlesPayerEmail() const {
  return false;
}

bool AndroidPaymentApp::HandlesPayerPhone() const {
  return false;
}

bool AndroidPaymentApp::IsWaitingForPaymentDetailsUpdate() const {
  return false;
}

void AndroidPaymentApp::UpdateWith(
    mojom::PaymentRequestDetailsUpdatePtr details_update) {
  // TODO(crbug.com/1022512): Support payment method, shipping address, and
  // shipping option change events.
}

void AndroidPaymentApp::OnPaymentDetailsNotUpdated() {}

bool AndroidPaymentApp::IsPreferred() const {
  // This class used only on Chrome OS, where the only Android payment app
  // available is the trusted web application (TWA) that launched this instance
  // of Chrome with a TWA specific payment method, so this app should be
  // preferred.
#if !defined(OS_CHROMEOS)
  NOTREACHED();
#endif  // OS_CHROMEOS
  DCHECK_EQ(1U, GetAppMethodNames().size());
  DCHECK_EQ(methods::kGooglePlayBilling, *GetAppMethodNames().begin());
  return true;
}

void AndroidPaymentApp::OnPaymentAppResponse(
    Delegate* delegate,
    const base::Optional<std::string>& error_message,
    bool is_activity_result_ok,
    const std::string& payment_method_identifier,
    const std::string& stringified_details) {
  if (error_message.has_value()) {
    delegate->OnInstrumentDetailsError(error_message.value());
    return;
  }

  if (!is_activity_result_ok) {
    delegate->OnInstrumentDetailsError(errors::kUserClosedPaymentApp);
    return;
  }

  delegate->OnInstrumentDetailsReady(payment_method_identifier,
                                     stringified_details, PayerData());
}

}  // namespace payments
