// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/payments/content/android_payment_app.h"

#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "base/bind.h"
#include "base/callback.h"
#include "base/optional.h"
#include "components/payments/content/android_app_communication.h"
#include "components/payments/content/android_app_communication_test_support.h"
#include "components/payments/core/android_app_description.h"
#include "components/payments/core/method_strings.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace payments {
namespace {

class AndroidPaymentAppTest : public testing::Test,
                              public PaymentApp::Delegate {
 public:
  static std::unique_ptr<AndroidPaymentApp> CreateAndroidPaymentApp(
      base::WeakPtr<AndroidAppCommunication> communication) {
    std::set<std::string> payment_method_names;
    payment_method_names.insert(methods::kGooglePlayBilling);
    auto stringified_method_data =
        std::make_unique<std::map<std::string, std::set<std::string>>>();
    stringified_method_data->insert({methods::kGooglePlayBilling, {"{}"}});
    auto description = std::make_unique<AndroidAppDescription>();
    description->package = "com.example.app";
    description->service_names.push_back("com.example.app.Service");
    description->activities.emplace_back(
        std::make_unique<AndroidActivityDescription>());
    description->activities.back()->name = "com.example.app.Activity";
    description->activities.back()->default_payment_method =
        methods::kGooglePlayBilling;

    return std::make_unique<AndroidPaymentApp>(
        payment_method_names, std::move(stringified_method_data),
        GURL("https://top-level-origin.com"),
        GURL("https://payment-request-origin.com"), "payment-request-id",
        std::move(description), communication);
  }

  AndroidPaymentAppTest()
      : support_(AndroidAppCommunicationTestSupport::Create()) {}

  ~AndroidPaymentAppTest() override = default;

  AndroidPaymentAppTest(const AndroidPaymentAppTest& other) = delete;
  AndroidPaymentAppTest& operator=(const AndroidPaymentAppTest& other) = delete;

  // PaymentApp::Delegate implementation.
  void OnInstrumentDetailsReady(const std::string& method_name,
                                const std::string& stringified_details,
                                const PayerData& payer_data) override {
    method_name_ = method_name;
    stringified_details_ = stringified_details;
  }

  // PaymentApp::Delegate implementation.
  void OnInstrumentDetailsError(const std::string& error_message) override {
    error_message_ = error_message;
  }

  std::unique_ptr<AndroidAppCommunicationTestSupport> support_;
  std::unique_ptr<AndroidAppCommunicationTestSupport::ScopedInitialization>
      scoped_initialization_;
  base::WeakPtr<AndroidAppCommunication> communication_;
  std::string method_name_;
  std::string stringified_details_;
  std::string error_message_;
};

TEST_F(AndroidPaymentAppTest, BrowserShutdown) {
  // Explicitly do not initialize AndroidAppCommunication. This can happen
  // during browser shutdown.
  scoped_initialization_ = support_->CreateScopedInitialization();

  support_->ExpectNoPaymentAppInvoke();

  auto app = CreateAndroidPaymentApp(communication_);
  app->InvokePaymentApp(/*delegate=*/this);

  EXPECT_TRUE(error_message_.empty());
  EXPECT_TRUE(method_name_.empty());
  EXPECT_TRUE(stringified_details_.empty());
}

TEST_F(AndroidPaymentAppTest, UnableToCommunicateToAndroidApps) {
  communication_ =
      AndroidAppCommunication::GetForBrowserContext(support_->context());
  communication_->SetForTesting();
  // Explicitly do not create ScopedInitialization.

  support_->ExpectNoPaymentAppInvoke();

  auto app = CreateAndroidPaymentApp(communication_);
  app->InvokePaymentApp(/*delegate=*/this);

  EXPECT_EQ("Unable to invoke Android apps.", error_message_);
  EXPECT_TRUE(method_name_.empty());
  EXPECT_TRUE(stringified_details_.empty());
}

TEST_F(AndroidPaymentAppTest, OnInstrumentDetailsError) {
  communication_ =
      AndroidAppCommunication::GetForBrowserContext(support_->context());
  communication_->SetForTesting();
  scoped_initialization_ = support_->CreateScopedInitialization();

  support_->ExpectInvokePaymentAppAndRespond(
      /*is_activity_result_ok=*/false,
      /*payment_method_identifier=*/methods::kGooglePlayBilling,
      /*stringified_details=*/"{}");

  auto app = CreateAndroidPaymentApp(communication_);
  app->InvokePaymentApp(/*delegate=*/this);

  if (support_->AreAndroidAppsSupportedOnThisPlatform()) {
    EXPECT_EQ("User closed the payment app.", error_message_);
  } else {
    EXPECT_EQ("Unable to invoke Android apps.", error_message_);
  }

  EXPECT_TRUE(method_name_.empty());
  EXPECT_TRUE(stringified_details_.empty());
}

TEST_F(AndroidPaymentAppTest, OnInstrumentDetailsReady) {
  communication_ =
      AndroidAppCommunication::GetForBrowserContext(support_->context());
  communication_->SetForTesting();
  scoped_initialization_ = support_->CreateScopedInitialization();

  support_->ExpectInvokePaymentAppAndRespond(
      /*is_activity_result_ok=*/true,
      /*payment_method_identifier=*/methods::kGooglePlayBilling,
      /*stringified_details=*/"{\"status\": \"ok\"}");

  auto app = CreateAndroidPaymentApp(communication_);
  app->InvokePaymentApp(/*delegate=*/this);

  if (support_->AreAndroidAppsSupportedOnThisPlatform()) {
    EXPECT_TRUE(error_message_.empty());
    EXPECT_EQ(methods::kGooglePlayBilling, method_name_);
    EXPECT_EQ("{\"status\": \"ok\"}", stringified_details_);
  } else {
    EXPECT_EQ("Unable to invoke Android apps.", error_message_);
    EXPECT_TRUE(method_name_.empty());
    EXPECT_TRUE(stringified_details_.empty());
  }
}

}  // namespace
}  // namespace payments
