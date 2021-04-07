// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/payments/content/android_app_communication_test_support.h"

#include <utility>

#include "components/arc/mojom/payment_app.mojom.h"
#include "components/arc/pay/arc_payment_app_bridge.h"
#include "components/arc/test/arc_payment_app_bridge_test_support.h"
#include "components/payments/core/method_strings.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace payments {
namespace {

class ScopedInitializationChromeOS
    : public AndroidAppCommunicationTestSupport::ScopedInitialization {
 public:
  ScopedInitializationChromeOS(arc::ArcServiceManager* manager,
                               arc::mojom::PaymentAppInstance* instance)
      : scoped_set_instance_(manager, instance) {}
  ~ScopedInitializationChromeOS() override = default;

  ScopedInitializationChromeOS(const ScopedInitializationChromeOS& other) =
      delete;
  ScopedInitializationChromeOS& operator=(
      const ScopedInitializationChromeOS& other) = delete;

 private:
  arc::ArcPaymentAppBridgeTestSupport::ScopedSetInstance scoped_set_instance_;
};

class AndroidAppCommunicationTestSupportChromeOS
    : public AndroidAppCommunicationTestSupport {
 public:
  AndroidAppCommunicationTestSupportChromeOS() = default;
  ~AndroidAppCommunicationTestSupportChromeOS() override = default;

  AndroidAppCommunicationTestSupportChromeOS(
      const AndroidAppCommunicationTestSupportChromeOS& other) = delete;
  AndroidAppCommunicationTestSupportChromeOS& operator=(
      const AndroidAppCommunicationTestSupportChromeOS& other) = delete;

  bool AreAndroidAppsSupportedOnThisPlatform() const override { return true; }

  std::unique_ptr<ScopedInitialization> CreateScopedInitialization() override {
    return std::make_unique<ScopedInitializationChromeOS>(support_.manager(),
                                                          support_.instance());
  }

  void ExpectNoListOfPaymentAppsQuery() override {
    EXPECT_CALL(*support_.instance(),
                IsPaymentImplemented(testing::_, testing::_))
        .Times(0);
  }

  void ExpectNoIsReadyToPayQuery() override {
    EXPECT_CALL(*support_.instance(), IsReadyToPay(testing::_, testing::_))
        .Times(0);
  }

  void ExpectNoPaymentAppInvoke() override {
    EXPECT_CALL(*support_.instance(), InvokePaymentApp(testing::_, testing::_))
        .Times(0);
  }

  void ExpectQueryListOfPaymentAppsAndRespond(
      std::vector<std::unique_ptr<AndroidAppDescription>> apps) override {
    // Move |apps| into a member variable, so it's still alive by the time the
    // RespondToGetAppDescriptions() method is executed at some point in the
    // future.
    apps_ = std::move(apps);
    EXPECT_CALL(*support_.instance(),
                IsPaymentImplemented(testing::_, testing::_))
        .WillOnce(testing::Invoke(
            [&](const std::string& package_name,
                arc::ArcPaymentAppBridge::IsPaymentImplementedCallback
                    callback) {
              RespondToGetAppDescriptions(package_name, std::move(callback));
            }));
  }

  void ExpectQueryIsReadyToPayAndRespond(bool is_ready_to_pay) override {
    EXPECT_CALL(*support_.instance(), IsReadyToPay(testing::_, testing::_))
        .WillOnce(testing::Invoke(
            [is_ready_to_pay](
                arc::mojom::PaymentParametersPtr parameters,
                arc::ArcPaymentAppBridge::IsReadyToPayCallback callback) {
              std::move(callback).Run(
                  arc::mojom::IsReadyToPayResult::NewResponse(is_ready_to_pay));
            }));
  }

  void ExpectInvokePaymentAppAndRespond(
      bool is_activity_result_ok,
      const std::string& payment_method_identifier,
      const std::string& stringified_details) override {
    EXPECT_CALL(*support_.instance(), InvokePaymentApp(testing::_, testing::_))
        .WillOnce(testing::Invoke(
            [is_activity_result_ok, stringified_details](
                arc::mojom::PaymentParametersPtr parameters,
                arc::ArcPaymentAppBridge::InvokePaymentAppCallback callback) {
              // Chrome OS supports only kGooglePlayBilling payment method
              // identifier at this time, so the |payment_method_identifier|
              // parameter is ignored here.
              auto valid = arc::mojom::InvokePaymentAppValidResult::New();
              valid->is_activity_result_ok = is_activity_result_ok;
              valid->stringified_details = stringified_details;
              std::move(callback).Run(
                  arc::mojom::InvokePaymentAppResult::NewValid(
                      std::move(valid)));
            }));
  }

  content::BrowserContext* context() override { return support_.context(); }

 private:
  void RespondToGetAppDescriptions(
      const std::string& package_name,
      arc::ArcPaymentAppBridge::IsPaymentImplementedCallback callback) {
    auto valid = arc::mojom::IsPaymentImplementedValidResult::New();
    for (const auto& app : apps_) {
      if (app->package == package_name) {
        for (const auto& activity : app->activities) {
          // Chrome OS supports only kGooglePlayBilling method at this time.
          if (activity->default_payment_method == methods::kGooglePlayBilling) {
            valid->activity_names.push_back(activity->name);
          }
        }

        valid->service_names = app->service_names;

        // Chrome OS supports only one payment app in Android subsystem at this
        // time, i.e., the TWA that invoked Chrome.
        break;
      }
    }

    std::move(callback).Run(
        arc::mojom::IsPaymentImplementedResult::NewValid(std::move(valid)));
  }

  arc::ArcPaymentAppBridgeTestSupport support_;
  std::vector<std::unique_ptr<AndroidAppDescription>> apps_;
};

}  // namespace

// Declared in cross-platform file
// //components/payments/content/android_app_communication_test_support.h
// static
std::unique_ptr<AndroidAppCommunicationTestSupport>
AndroidAppCommunicationTestSupport::Create() {
  return std::make_unique<AndroidAppCommunicationTestSupportChromeOS>();
}

}  // namespace payments
