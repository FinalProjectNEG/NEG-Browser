// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/webui/chromeos/edu_coexistence_login_handler_chromeos.h"

#include <memory>
#include <string>

#include "base/bind_helpers.h"
#include "base/test/scoped_feature_list.h"
#include "base/time/time.h"
#include "chrome/browser/chromeos/login/test/fake_gaia_mixin.h"
#include "chrome/browser/supervised_user/logged_in_user_mixin.h"
#include "chrome/browser/supervised_user/supervised_user_features.h"
#include "chrome/browser/supervised_user/supervised_user_service.h"
#include "chrome/browser/ui/browser.h"
#include "chrome/browser/ui/webui/chromeos/edu_coexistence_consent_tracker.h"
#include "chrome/test/base/in_process_browser_test.h"
#include "chrome/test/base/mixin_based_in_process_browser_test.h"
#include "chrome/test/base/ui_test_utils.h"
#include "components/signin/public/identity_manager/access_token_info.h"
#include "components/signin/public/identity_manager/account_info.h"
#include "content/public/browser/web_contents.h"
#include "content/public/test/browser_test.h"
#include "content/public/test/browser_test_utils.h"
#include "content/public/test/test_web_ui.h"
#include "google_apis/gaia/google_service_auth_error.h"

namespace chromeos {

namespace {

constexpr char kResponseCallback[] = "cr.webUIResponse";

}  // namespace

class EduCoexistenceLoginHandlerBrowserTest
    : public MixinBasedInProcessBrowserTest {
 public:
  EduCoexistenceLoginHandlerBrowserTest() = default;
  EduCoexistenceLoginHandlerBrowserTest(
      const EduCoexistenceLoginHandlerBrowserTest&) = delete;
  EduCoexistenceLoginHandlerBrowserTest& operator=(
      const EduCoexistenceLoginHandlerBrowserTest&) = delete;
  ~EduCoexistenceLoginHandlerBrowserTest() override = default;

  void SetUp() override {
    scoped_feature_list_.InitAndEnableFeature(
        supervised_users::kEduCoexistenceFlowV2);

    MixinBasedInProcessBrowserTest::SetUp();
  }

  void SetUpOnMainThread() override {
    MixinBasedInProcessBrowserTest::SetUpOnMainThread();
    logged_in_user_mixin_.LogInUser();
  }

  void TearDown() override { MixinBasedInProcessBrowserTest::TearDown(); }

  std::unique_ptr<EduCoexistenceLoginHandler> SetUpHandler() {
    auto handler =
        std::make_unique<EduCoexistenceLoginHandler>(base::DoNothing());
    handler->set_web_ui_for_test(web_ui());
    handler->RegisterMessages();
    return handler;
  }

  void VerifyJavascriptCallResolved(const content::TestWebUI::CallData& data,
                                    const std::string& event_name,
                                    const std::string& call_type) {
    EXPECT_EQ(call_type, data.function_name());

    std::string callback_id;
    ASSERT_TRUE(data.arg1()->GetAsString(&callback_id));
    EXPECT_EQ(event_name, callback_id);
  }

  void SimulateAccessTokenFetched(EduCoexistenceLoginHandler* handler,
                                  bool success = true) {
    GoogleServiceAuthError::State state =
        success ? GoogleServiceAuthError::NONE
                : GoogleServiceAuthError::INVALID_GAIA_CREDENTIALS;

    handler->OnOAuthAccessTokensFetched(
        GoogleServiceAuthError(state),
        signin::AccessTokenInfo(
            "access_token", base::Time::Now() + base::TimeDelta::FromMinutes(1),
            ""));
  }

 protected:
  content::TestWebUI* web_ui() { return &web_ui_; }

 private:
  base::test::ScopedFeatureList scoped_feature_list_;

  chromeos::LoggedInUserMixin logged_in_user_mixin_{
      &mixin_host_, chromeos::LoggedInUserMixin::LogInType::kChild,
      embedded_test_server(), this};

  content::TestWebUI web_ui_;
};

IN_PROC_BROWSER_TEST_F(EduCoexistenceLoginHandlerBrowserTest,
                       HandleInitializeEduCoexistenceArgs) {
  std::unique_ptr<EduCoexistenceLoginHandler> handler = SetUpHandler();

  constexpr char callback_id[] = "coexistence-data-init";
  base::ListValue list_args;
  list_args.Append(callback_id);
  web_ui()->HandleReceivedMessage("initializeEduArgs", &list_args);
  SimulateAccessTokenFetched(handler.get());

  EXPECT_EQ(web_ui()->call_data().size(), 1u);

  const content::TestWebUI::CallData& second_call = *web_ui()->call_data()[0];

  // TODO(yilkal): verify the exact the call arguments.
  VerifyJavascriptCallResolved(second_call, callback_id, kResponseCallback);
}

// TODO(yilkal): Add test to cover for when OauthAccessTokenFetchFails.

IN_PROC_BROWSER_TEST_F(EduCoexistenceLoginHandlerBrowserTest,
                       HandleConsentLogged) {
  std::unique_ptr<EduCoexistenceLoginHandler> handler = SetUpHandler();
  constexpr char consentLoggedCallback[] = "consent-logged-callback";

  base::ListValue call_args;
  call_args.Append(FakeGaiaMixin::kFakeUserEmail);
  call_args.Append("12345678");

  base::ListValue list_args;
  list_args.Append(consentLoggedCallback);
  list_args.Append(std::move(call_args));

  web_ui()->HandleReceivedMessage("consentLogged", &list_args);
  SimulateAccessTokenFetched(handler.get());

  const EduCoexistenceConsentTracker::EmailAndCallback* tracker =
      EduCoexistenceConsentTracker::Get()->GetInfoForWebUIForTest(web_ui());

  // Ensure that the tracker gets the appropriate update.
  EXPECT_NE(tracker, nullptr);
  EXPECT_TRUE(tracker->received_consent);
  EXPECT_EQ(tracker->email, FakeGaiaMixin::kFakeUserEmail);

  // Simulate account added.
  CoreAccountInfo account;
  account.email = FakeGaiaMixin::kFakeUserEmail;
  handler->OnRefreshTokenUpdatedForAccount(account);

  EXPECT_EQ(web_ui()->call_data().size(), 1u);
  const content::TestWebUI::CallData& second_call = *web_ui()->call_data()[0];

  // TODO(yilkal): verify the exact the call arguments.
  VerifyJavascriptCallResolved(second_call, consentLoggedCallback,
                               kResponseCallback);
}

}  // namespace chromeos
