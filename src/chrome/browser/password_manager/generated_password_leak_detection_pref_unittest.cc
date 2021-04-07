// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/password_manager/generated_password_leak_detection_pref.h"
#include "chrome/browser/extensions/api/settings_private/generated_pref_test_base.h"
#include "chrome/browser/extensions/api/settings_private/generated_prefs_factory.h"
#include "chrome/browser/signin/identity_test_environment_profile_adaptor.h"
#include "chrome/browser/sync/profile_sync_service_factory.h"
#include "chrome/test/base/testing_profile.h"
#include "components/password_manager/core/common/password_manager_pref_names.h"
#include "components/safe_browsing/core/common/safe_browsing_prefs.h"
#include "components/signin/public/identity_manager/identity_test_environment.h"
#include "components/sync/driver/test_sync_service.h"
#include "components/sync_preferences/testing_pref_service_syncable.h"
#include "content/public/test/browser_task_environment.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace {

std::unique_ptr<KeyedService> BuildTestSyncService(
    content::BrowserContext* context) {
  return std::make_unique<syncer::TestSyncService>();
}

}  // namespace

namespace settings_api = extensions::api::settings_private;
namespace settings_private = extensions::settings_private;

class GeneratedPasswordLeakDetectionPrefTest : public testing::Test {
 public:
  signin::IdentityTestEnvironment* identity_test_env() {
    return identity_test_env_adaptor_->identity_test_env();
  }

  sync_preferences::TestingPrefServiceSyncable* prefs() {
    return profile_->GetTestingPrefService();
  }

  TestingProfile* profile() { return profile_.get(); }

  syncer::TestSyncService* sync_service() { return sync_service_; }

  content::BrowserTaskEnvironment task_environment_;

 private:
  std::unique_ptr<TestingProfile> profile_ =
      IdentityTestEnvironmentProfileAdaptor::
          CreateProfileForIdentityTestEnvironment({});
  syncer::TestSyncService* sync_service_ =
      static_cast<syncer::TestSyncService*>(
          ProfileSyncServiceFactory::GetInstance()->SetTestingFactoryAndUse(
              profile(),
              base::BindRepeating(&BuildTestSyncService)));
  std::unique_ptr<IdentityTestEnvironmentProfileAdaptor>
      identity_test_env_adaptor_ =
          std::make_unique<IdentityTestEnvironmentProfileAdaptor>(
              profile_.get());
};

TEST_F(GeneratedPasswordLeakDetectionPrefTest, NotifyPrefUpdates) {
  // Check that when source information changes, the pref observer is fired.
  GeneratedPasswordLeakDetectionPref pref(profile());
  settings_private::TestGeneratedPrefObserver test_observer;
  pref.AddObserver(&test_observer);

  // Check that the observer fires for identity updates.
  identity_test_env()->EnableRemovalOfExtendedAccountInfo();
  identity_test_env()->MakePrimaryAccountAvailable("test@test.com");
  EXPECT_EQ(test_observer.GetUpdatedPrefName(),
            kGeneratedPasswordLeakDetectionPref);

  test_observer.Reset();
  identity_test_env()->RemoveRefreshTokenForPrimaryAccount();
  EXPECT_EQ(test_observer.GetUpdatedPrefName(),
            kGeneratedPasswordLeakDetectionPref);

#if !defined(OS_CHROMEOS)
  // Clearing the primary account does not make sense on ChromeOS.
  test_observer.Reset();
  identity_test_env()->ClearPrimaryAccount();
  EXPECT_EQ(test_observer.GetUpdatedPrefName(),
            kGeneratedPasswordLeakDetectionPref);
#endif  // !defined (OS_CHROMEOS)

  // Check the observer fires for source preference updates.
  test_observer.Reset();
  prefs()->SetUserPref(prefs::kSafeBrowsingEnabled,
                       std::make_unique<base::Value>(true));
  EXPECT_EQ(test_observer.GetUpdatedPrefName(),
            kGeneratedPasswordLeakDetectionPref);

  test_observer.Reset();
  prefs()->SetUserPref(prefs::kSafeBrowsingEnhanced,
                       std::make_unique<base::Value>(true));
  EXPECT_EQ(test_observer.GetUpdatedPrefName(),
            kGeneratedPasswordLeakDetectionPref);

  test_observer.Reset();
  prefs()->SetUserPref(password_manager::prefs::kPasswordLeakDetectionEnabled,
                       std::make_unique<base::Value>(true));
  EXPECT_EQ(test_observer.GetUpdatedPrefName(),
            kGeneratedPasswordLeakDetectionPref);

  // // Check the observer fires for sync service updates.
  test_observer.Reset();
  sync_service()->FireStateChanged();
  EXPECT_EQ(test_observer.GetUpdatedPrefName(),
            kGeneratedPasswordLeakDetectionPref);
}

TEST_F(GeneratedPasswordLeakDetectionPrefTest, UpdatePreference) {
  // Check the generated pref both updates, and respects updates to, the
  // underlying preference.
  GeneratedPasswordLeakDetectionPref pref(profile());

  // Setup baseline profile preference & signin state.
  prefs()->SetDefaultPrefValue(
      password_manager::prefs::kPasswordLeakDetectionEnabled,
      base::Value(false));
  identity_test_env()->MakePrimaryAccountAvailable("test@test.com");

  // Check setting the generated pref updates the underlying preference.
  EXPECT_EQ(pref.SetPref(std::make_unique<base::Value>(true).get()),
            settings_private::SetPrefResult::SUCCESS);
  EXPECT_TRUE(
      prefs()
          ->GetUserPref(password_manager::prefs::kPasswordLeakDetectionEnabled)
          ->GetBool());

  EXPECT_EQ(pref.SetPref(std::make_unique<base::Value>(false).get()),
            settings_private::SetPrefResult::SUCCESS);
  EXPECT_FALSE(
      prefs()
          ->GetUserPref(password_manager::prefs::kPasswordLeakDetectionEnabled)
          ->GetBool());

  // Check that changing the underlying preference correctly updates the
  // generated pref.
  prefs()->SetUserPref(password_manager::prefs::kPasswordLeakDetectionEnabled,
                       std::make_unique<base::Value>(true));
  EXPECT_TRUE(pref.GetPrefObject()->value->GetBool());

  prefs()->SetUserPref(password_manager::prefs::kPasswordLeakDetectionEnabled,
                       std::make_unique<base::Value>(false));
  EXPECT_FALSE(pref.GetPrefObject()->value->GetBool());

  // Confirm that a type mismatch is reported as such.
  EXPECT_EQ(pref.SetPref(std::make_unique<base::Value>(2).get()),
            extensions::settings_private::SetPrefResult::PREF_TYPE_MISMATCH);
}

TEST_F(GeneratedPasswordLeakDetectionPrefTest, ProfileState) {
  // Check preference is disabled when the profile is not signed in, or when
  // Safe Browsing is not set to Standard.
  GeneratedPasswordLeakDetectionPref pref(profile());
  prefs()->SetUserPref(password_manager::prefs::kPasswordLeakDetectionEnabled,
                       std::make_unique<base::Value>(true));

  // Check when signed in and Safe Browsing set to standard, both user control
  // and the pref are enabled.
  identity_test_env()->MakePrimaryAccountAvailable("test@test.com");
  prefs()->SetUserPref(prefs::kSafeBrowsingEnabled,
                       std::make_unique<base::Value>(true));
  prefs()->SetUserPref(prefs::kSafeBrowsingEnhanced,
                       std::make_unique<base::Value>(false));
  EXPECT_TRUE(pref.GetPrefObject()->value->GetBool());
  EXPECT_FALSE(*pref.GetPrefObject()->user_control_disabled);

  // Set Safe Browsing to disabled and check user control is disabled, but that
  // the pref remains enabled.
  prefs()->SetUserPref(prefs::kSafeBrowsingEnabled,
                       std::make_unique<base::Value>(false));
  EXPECT_TRUE(pref.GetPrefObject()->value->GetBool());
  EXPECT_TRUE(*pref.GetPrefObject()->user_control_disabled);

  // Reset Safe Browsing to standard and turn off sync, ensure both user control
  // and the preference are disabled.
  sync_service()->GetUserSettings()->SetSyncRequested(false);
  prefs()->SetUserPref(prefs::kSafeBrowsingEnabled,
                       std::make_unique<base::Value>(true));
  EXPECT_FALSE(pref.GetPrefObject()->value->GetBool());
  EXPECT_TRUE(*pref.GetPrefObject()->user_control_disabled);

  // Ensure when the pref is disabled by profile state is cannot be modified.
  EXPECT_EQ(pref.SetPref(std::make_unique<base::Value>(true).get()),
            settings_private::SetPrefResult::PREF_NOT_MODIFIABLE);
}

TEST_F(GeneratedPasswordLeakDetectionPrefTest, ManagementState) {
  // Check that the management state of the underlying preference is applied
  // to the generated preference.
  GeneratedPasswordLeakDetectionPref pref(profile());
  EXPECT_EQ(pref.GetPrefObject()->enforcement,
            settings_api::Enforcement::ENFORCEMENT_NONE);
  EXPECT_EQ(pref.GetPrefObject()->controlled_by,
            settings_api::ControlledBy::CONTROLLED_BY_NONE);

  prefs()->SetRecommendedPref(
      password_manager::prefs::kPasswordLeakDetectionEnabled,
      std::make_unique<base::Value>(true));
  EXPECT_EQ(pref.GetPrefObject()->enforcement,
            settings_api::Enforcement::ENFORCEMENT_RECOMMENDED);
  EXPECT_EQ(pref.GetPrefObject()->recommended_value->GetBool(), true);

  prefs()->SetManagedPref(
      password_manager::prefs::kPasswordLeakDetectionEnabled,
      std::make_unique<base::Value>(true));
  EXPECT_EQ(pref.GetPrefObject()->enforcement,
            settings_api::Enforcement::ENFORCEMENT_ENFORCED);
  EXPECT_EQ(pref.GetPrefObject()->controlled_by,
            settings_api::ControlledBy::CONTROLLED_BY_DEVICE_POLICY);

  // Check that the preference cannot be changed when the backing preference is
  // managed, but the preference could otherwise be changed.
  identity_test_env()->MakePrimaryAccountAvailable("test@test.com");
  prefs()->SetUserPref(prefs::kSafeBrowsingEnabled,
                       std::make_unique<base::Value>(true));
  prefs()->SetUserPref(prefs::kSafeBrowsingEnhanced,
                       std::make_unique<base::Value>(false));
  EXPECT_EQ(pref.SetPref(std::make_unique<base::Value>(true).get()),
            settings_private::SetPrefResult::PREF_NOT_MODIFIABLE);
}
