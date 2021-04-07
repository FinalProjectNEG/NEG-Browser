// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/password_manager/android/save_password_infobar_delegate_android.h"

#include <memory>
#include <string>
#include <utility>

#include "base/macros.h"
#include "base/strings/utf_string_conversions.h"
#include "base/test/metrics/histogram_tester.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/grit/generated_resources.h"
#include "chrome/test/base/chrome_render_view_host_test_harness.h"
#include "components/autofill/core/common/form_data.h"
#include "components/password_manager/core/browser/fake_form_fetcher.h"
#include "components/password_manager/core/browser/password_form.h"
#include "components/password_manager/core/browser/password_form_manager.h"
#include "components/password_manager/core/browser/password_manager_metrics_util.h"
#include "components/password_manager/core/browser/password_save_manager_impl.h"
#include "components/password_manager/core/browser/stub_form_saver.h"
#include "components/password_manager/core/browser/stub_password_manager_client.h"
#include "components/password_manager/core/browser/stub_password_manager_driver.h"
#include "components/password_manager/core/common/password_manager_pref_names.h"
#include "components/prefs/pref_service.h"
#include "components/ukm/test_ukm_recorder.h"
#include "content/public/browser/web_contents.h"
#include "services/metrics/public/cpp/ukm_source.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "ui/base/l10n/l10n_util.h"

using password_manager::PasswordFormManager;
using password_manager::PasswordFormMetricsRecorder;
using password_manager::PasswordSaveManagerImpl;

namespace {

// TODO(crbug.com/1086479): Replace this with MockPasswordFormManagerForUI.
class MockPasswordFormManager : public PasswordFormManager {
 public:
  MOCK_METHOD(bool, WasUnblacklisted, (), (const, override));
  MOCK_METHOD(void, PermanentlyBlacklist, (), (override));

  MockPasswordFormManager(
      password_manager::PasswordManagerClient* client,
      base::WeakPtr<password_manager::PasswordManagerDriver> driver,
      const autofill::FormData& form,
      password_manager::FormFetcher* form_fetcher,
      scoped_refptr<PasswordFormMetricsRecorder> metrics_recorder)
      : PasswordFormManager(
            client,
            driver,
            form,
            form_fetcher,
            std::make_unique<PasswordSaveManagerImpl>(
                std::make_unique<password_manager::StubFormSaver>()),
            metrics_recorder) {}

  // Constructor for federation credentials.
  MockPasswordFormManager(password_manager::PasswordManagerClient* client,
                          const password_manager::PasswordForm& form)
      : PasswordFormManager(
            client,
            std::make_unique<password_manager::PasswordForm>(form),
            std::make_unique<password_manager::FakeFormFetcher>(),
            std::make_unique<PasswordSaveManagerImpl>(
                std::make_unique<password_manager::StubFormSaver>())) {
    CreatePendingCredentials();
  }

  ~MockPasswordFormManager() override = default;

 private:
  DISALLOW_COPY_AND_ASSIGN(MockPasswordFormManager);
};

class TestSavePasswordInfoBarDelegate : public SavePasswordInfoBarDelegate {
 public:
  TestSavePasswordInfoBarDelegate(
      content::WebContents* web_contents,
      std::unique_ptr<password_manager::PasswordFormManager> form_to_save,
      bool is_smartlock_branding_enabled)
      : SavePasswordInfoBarDelegate(web_contents,
                                    std::move(form_to_save),
                                    is_smartlock_branding_enabled) {}

  ~TestSavePasswordInfoBarDelegate() override = default;
};

}  // namespace

class SavePasswordInfoBarDelegateTest : public ChromeRenderViewHostTestHarness {
 public:
  SavePasswordInfoBarDelegateTest();
  ~SavePasswordInfoBarDelegateTest() override = default;

  void SetUp() override;
  void TearDown() override;

  PrefService* prefs();
  const password_manager::PasswordForm& test_form() { return test_form_; }
  std::unique_ptr<MockPasswordFormManager> CreateMockFormManager(
      scoped_refptr<PasswordFormMetricsRecorder> metrics_recorder,
      bool with_federation_origin);

 protected:
  std::unique_ptr<PasswordManagerInfoBarDelegate> CreateDelegate(
      std::unique_ptr<password_manager::PasswordFormManager>
          password_form_manager,
      bool is_smartlock_branding_enabled);

  password_manager::StubPasswordManagerClient client_;
  password_manager::StubPasswordManagerDriver driver_;

  password_manager::PasswordForm test_form_;
  autofill::FormData observed_form_;

 private:
  password_manager::FakeFormFetcher fetcher_;

  DISALLOW_COPY_AND_ASSIGN(SavePasswordInfoBarDelegateTest);
};

SavePasswordInfoBarDelegateTest::SavePasswordInfoBarDelegateTest() {
  test_form_.url = GURL("https://example.com");
  test_form_.username_value = base::ASCIIToUTF16("username");
  test_form_.password_value = base::ASCIIToUTF16("12345");

  // Create a simple sign-in form.
  observed_form_.url = test_form_.url;
  autofill::FormFieldData field;
  field.form_control_type = "text";
  field.value = test_form_.username_value;
  observed_form_.fields.push_back(field);
  field.form_control_type = "password";
  field.value = test_form_.password_value;
  observed_form_.fields.push_back(field);

  // Turn off waiting for server predictions in order to avoid dealing with
  // posted tasks in PasswordFormManager.
  PasswordFormManager::set_wait_for_server_predictions_for_filling(false);
}

PrefService* SavePasswordInfoBarDelegateTest::prefs() {
  Profile* profile =
      Profile::FromBrowserContext(web_contents()->GetBrowserContext());
  return profile->GetPrefs();
}

std::unique_ptr<MockPasswordFormManager>
SavePasswordInfoBarDelegateTest::CreateMockFormManager(
    scoped_refptr<PasswordFormMetricsRecorder> metrics_recorder,
    bool with_federation_origin) {
  if (with_federation_origin) {
    auto password_form = test_form();
    password_form.federation_origin =
        url::Origin::Create(GURL("https://example.com"));
    return std::make_unique<MockPasswordFormManager>(&client_, password_form);
  }
  auto manager = std::make_unique<MockPasswordFormManager>(
      &client_, driver_.AsWeakPtr(), observed_form_, &fetcher_,
      metrics_recorder);
  manager->ProvisionallySave(observed_form_, &driver_, nullptr);
  return manager;
}

std::unique_ptr<PasswordManagerInfoBarDelegate>
SavePasswordInfoBarDelegateTest::CreateDelegate(
    std::unique_ptr<password_manager::PasswordFormManager>
        password_form_manager,
    bool is_smartlock_branding_enabled) {
  return std::make_unique<TestSavePasswordInfoBarDelegate>(
      web_contents(), std::move(password_form_manager),
      is_smartlock_branding_enabled);
}

void SavePasswordInfoBarDelegateTest::SetUp() {
  ChromeRenderViewHostTestHarness::SetUp();
}

void SavePasswordInfoBarDelegateTest::TearDown() {
  ChromeRenderViewHostTestHarness::TearDown();
}

TEST_F(SavePasswordInfoBarDelegateTest, CancelTest) {
  std::unique_ptr<MockPasswordFormManager> password_form_manager(
      CreateMockFormManager(nullptr, false /* with_federation_origin */));
  EXPECT_CALL(*password_form_manager.get(), PermanentlyBlacklist());
  std::unique_ptr<ConfirmInfoBarDelegate> infobar(
      CreateDelegate(std::move(password_form_manager),
                     true /* is_smartlock_branding_enabled */));
  EXPECT_TRUE(infobar->Cancel());
}

TEST_F(SavePasswordInfoBarDelegateTest, HasDetailsMessageWhenSyncing) {
  std::unique_ptr<MockPasswordFormManager> password_form_manager(
      CreateMockFormManager(nullptr, false /* with_federation_origin */));
  std::unique_ptr<PasswordManagerInfoBarDelegate> infobar(
      CreateDelegate(std::move(password_form_manager),
                     true /* is_smartlock_branding_enabled */));
  EXPECT_EQ(l10n_util::GetStringUTF16(IDS_SAVE_PASSWORD_FOOTER),
            infobar->GetDetailsMessageText());
}

TEST_F(SavePasswordInfoBarDelegateTest, EmptyDetailsMessageWhenNotSyncing) {
  std::unique_ptr<MockPasswordFormManager> password_form_manager(
      CreateMockFormManager(nullptr, false /* with_federation_origin */));
  std::unique_ptr<PasswordManagerInfoBarDelegate> infobar(
      CreateDelegate(std::move(password_form_manager),
                     false /* is_smartlock_branding_enabled */));
  EXPECT_TRUE(infobar->GetDetailsMessageText().empty());
}

TEST_F(SavePasswordInfoBarDelegateTest,
       EmptyDetailsMessageForFederatedCredentialsWhenSyncing) {
  std::unique_ptr<MockPasswordFormManager> password_form_manager(
      CreateMockFormManager(nullptr, true /* with_federation_origin */));
  NavigateAndCommit(GURL("https://example.com"));
  std::unique_ptr<PasswordManagerInfoBarDelegate> infobar(
      CreateDelegate(std::move(password_form_manager),
                     true /* is_smartlock_branding_enabled */));
  EXPECT_TRUE(infobar->GetDetailsMessageText().empty());
}

TEST_F(SavePasswordInfoBarDelegateTest,
       EmptyDetailsMessageForFederatedCredentialsWhenNotSyncing) {
  std::unique_ptr<MockPasswordFormManager> password_form_manager(
      CreateMockFormManager(nullptr, true /* with_federation_origin */));
  NavigateAndCommit(GURL("https://example.com"));
  std::unique_ptr<PasswordManagerInfoBarDelegate> infobar(
      CreateDelegate(std::move(password_form_manager),
                     false /* is_smartlock_branding_enabled */));
  EXPECT_TRUE(infobar->GetDetailsMessageText().empty());
}

TEST_F(SavePasswordInfoBarDelegateTest, RecordsSaveAfterUnblacklisting) {
  std::unique_ptr<MockPasswordFormManager> password_form_manager(
      CreateMockFormManager(nullptr, false /* with_federation_origin */));
  ON_CALL(*password_form_manager, WasUnblacklisted)
      .WillByDefault(testing::Return(true));
  std::unique_ptr<ConfirmInfoBarDelegate> infobar(
      CreateDelegate(std::move(password_form_manager),
                     false /* is_smartlock_branding_enabled */));
  base::HistogramTester histogram_tester;
  infobar->Accept();
  infobar.reset();
  histogram_tester.ExpectUniqueSample(
      "PasswordManager.SaveUIDismissalReasonAfterUnblacklisting",
      password_manager::metrics_util::CLICKED_ACCEPT, 1);
}

TEST_F(SavePasswordInfoBarDelegateTest, RecordNeverAfterUnblacklisting) {
  std::unique_ptr<MockPasswordFormManager> password_form_manager(
      CreateMockFormManager(nullptr, false /* with_federation_origin */));
  ON_CALL(*password_form_manager, WasUnblacklisted)
      .WillByDefault(testing::Return(true));
  std::unique_ptr<ConfirmInfoBarDelegate> infobar(
      CreateDelegate(std::move(password_form_manager),
                     false /* is_smartlock_branding_enabled */));
  base::HistogramTester histogram_tester;
  infobar->Cancel();
  infobar.reset();
  histogram_tester.ExpectUniqueSample(
      "PasswordManager.SaveUIDismissalReasonAfterUnblacklisting",
      password_manager::metrics_util::CLICKED_NEVER, 1);
}

TEST_F(SavePasswordInfoBarDelegateTest, RecordDismissAfterUnblacklisting) {
  std::unique_ptr<MockPasswordFormManager> password_form_manager(
      CreateMockFormManager(nullptr, false /* with_federation_origin */));
  ON_CALL(*password_form_manager, WasUnblacklisted)
      .WillByDefault(testing::Return(true));
  std::unique_ptr<ConfirmInfoBarDelegate> infobar(
      CreateDelegate(std::move(password_form_manager),
                     false /* is_smartlock_branding_enabled */));
  base::HistogramTester histogram_tester;
  infobar->InfoBarDismissed();
  infobar.reset();
  histogram_tester.ExpectUniqueSample(
      "PasswordManager.SaveUIDismissalReasonAfterUnblacklisting",
      password_manager::metrics_util::CLICKED_CANCEL, 1);
}

TEST_F(SavePasswordInfoBarDelegateTest, DontRecordIfNotUnblacklisted) {
  std::unique_ptr<MockPasswordFormManager> password_form_manager(
      CreateMockFormManager(nullptr, false /* with_federation_origin */));
  ON_CALL(*password_form_manager, WasUnblacklisted)
      .WillByDefault(testing::Return(false));
  std::unique_ptr<ConfirmInfoBarDelegate> infobar(
      CreateDelegate(std::move(password_form_manager),
                     false /* is_smartlock_branding_enabled */));
  base::HistogramTester histogram_tester;
  infobar->InfoBarDismissed();
  infobar.reset();
  histogram_tester.ExpectTotalCount(
      "PasswordManager.SaveUIDismissalReasonAfterUnblacklisting", 0);
}

class SavePasswordInfoBarDelegateTestForUKMs
    : public SavePasswordInfoBarDelegateTest,
      public ::testing::WithParamInterface<
          PasswordFormMetricsRecorder::BubbleDismissalReason> {
 public:
  SavePasswordInfoBarDelegateTestForUKMs() = default;
  ~SavePasswordInfoBarDelegateTestForUKMs() = default;
};

// Verify that URL keyed metrics are recorded for showing and interacting with
// the password save prompt.
TEST_P(SavePasswordInfoBarDelegateTestForUKMs, VerifyUKMRecording) {
  using BubbleTrigger = PasswordFormMetricsRecorder::BubbleTrigger;
  using BubbleDismissalReason =
      PasswordFormMetricsRecorder::BubbleDismissalReason;
  using UkmEntry = ukm::builders::PasswordForm;

  BubbleDismissalReason dismissal_reason = GetParam();
  SCOPED_TRACE(::testing::Message() << "dismissal_reason = "
                                    << static_cast<int64_t>(dismissal_reason));

  ukm::SourceId expected_source_id = ukm::UkmRecorder::GetNewSourceID();
  ukm::TestAutoSetUkmRecorder test_ukm_recorder;
  {
    // Setup metrics recorder
    auto recorder = base::MakeRefCounted<PasswordFormMetricsRecorder>(
        true /*is_main_frame_secure*/, expected_source_id,
        nullptr /* pref_service*/);

    // Exercise delegate.
    std::unique_ptr<MockPasswordFormManager> password_form_manager(
        CreateMockFormManager(recorder, false /* with_federation_origin */));
    if (dismissal_reason == BubbleDismissalReason::kDeclined)
      EXPECT_CALL(*password_form_manager.get(), PermanentlyBlacklist());
    std::unique_ptr<ConfirmInfoBarDelegate> infobar(
        CreateDelegate(std::move(password_form_manager),
                       true /* is_smartlock_branding_enabled */));
    switch (dismissal_reason) {
      case BubbleDismissalReason::kAccepted:
        EXPECT_TRUE(infobar->Accept());
        break;
      case BubbleDismissalReason::kDeclined:
        EXPECT_TRUE(infobar->Cancel());
        break;
      case BubbleDismissalReason::kIgnored:
        // Do nothing.
        break;
      case BubbleDismissalReason::kUnknown:
        NOTREACHED();
        break;
    }
  }

  // Verify metrics.
  const auto& entries =
      test_ukm_recorder.GetEntriesByName(UkmEntry::kEntryName);
  EXPECT_EQ(1u, entries.size());
  for (const auto* entry : entries) {
    EXPECT_EQ(expected_source_id, entry->source_id);
    test_ukm_recorder.ExpectEntryMetric(entry,
                                        UkmEntry::kSaving_Prompt_ShownName, 1);
    test_ukm_recorder.ExpectEntryMetric(
        entry, UkmEntry::kSaving_Prompt_TriggerName,
        static_cast<int64_t>(
            BubbleTrigger::kPasswordManagerSuggestionAutomatic));
    test_ukm_recorder.ExpectEntryMetric(
        entry, UkmEntry::kSaving_Prompt_InteractionName,
        static_cast<int64_t>(dismissal_reason));
  }
}

INSTANTIATE_TEST_SUITE_P(
    All,
    SavePasswordInfoBarDelegateTestForUKMs,
    ::testing::Values(
        PasswordFormMetricsRecorder::BubbleDismissalReason::kAccepted,
        PasswordFormMetricsRecorder::BubbleDismissalReason::kDeclined,
        PasswordFormMetricsRecorder::BubbleDismissalReason::kIgnored));
