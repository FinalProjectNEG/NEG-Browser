// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ash/assistant/assistant_state_controller.h"

#include <memory>
#include <string>

#include "ash/assistant/assistant_controller_impl.h"
#include "ash/session/session_controller_impl.h"
#include "ash/shell.h"
#include "ash/test/ash_test_base.h"
#include "base/macros.h"
#include "chromeos/services/assistant/public/cpp/assistant_prefs.h"
#include "components/prefs/pref_service.h"

namespace ash {

namespace {

using chromeos::assistant::prefs::AssistantOnboardingMode;
using chromeos::assistant::prefs::ConsentStatus;
using chromeos::assistant::prefs::kAssistantConsentStatus;
using chromeos::assistant::prefs::kAssistantContextEnabled;
using chromeos::assistant::prefs::kAssistantEnabled;
using chromeos::assistant::prefs::kAssistantHotwordAlwaysOn;
using chromeos::assistant::prefs::kAssistantHotwordEnabled;
using chromeos::assistant::prefs::kAssistantLaunchWithMicOpen;
using chromeos::assistant::prefs::kAssistantNotificationEnabled;
using chromeos::assistant::prefs::kAssistantOnboardingMode;
using chromeos::assistant::prefs::kAssistantOnboardingModeDefault;
using chromeos::assistant::prefs::kAssistantOnboardingModeEducation;

class TestAssistantStateObserver : public AssistantStateObserver {
 public:
  TestAssistantStateObserver() = default;
  ~TestAssistantStateObserver() override = default;

  // AssistantStateObserver:
  void OnAssistantConsentStatusChanged(int consent_status) override {
    consent_status_ = consent_status;
  }
  void OnAssistantContextEnabled(bool context_enabled) override {
    context_enabled_ = context_enabled;
  }
  void OnAssistantSettingsEnabled(bool settings_enabled) override {
    settings_enabled_ = settings_enabled;
  }
  void OnAssistantHotwordAlwaysOn(bool hotword_always_on) override {
    hotword_always_on_ = hotword_always_on;
  }
  void OnAssistantHotwordEnabled(bool hotword_enabled) override {
    hotword_enabled_ = hotword_enabled;
  }
  void OnAssistantLaunchWithMicOpen(bool launch_with_mic_open) override {
    launch_with_mic_open_ = launch_with_mic_open;
  }
  void OnAssistantNotificationEnabled(bool notification_enabled) override {
    notification_enabled_ = notification_enabled;
  }
  void OnAssistantOnboardingModeChanged(
      AssistantOnboardingMode onboarding_mode) override {
    onboarding_mode_ = onboarding_mode;
  }

  int consent_status() const { return consent_status_; }
  bool context_enabled() const { return context_enabled_; }
  bool settings_enabled() const { return settings_enabled_; }
  bool hotword_always_on() const { return hotword_always_on_; }
  bool hotword_enabled() const { return hotword_enabled_; }
  bool launch_with_mic_open() const { return launch_with_mic_open_; }
  bool notification_enabled() const { return notification_enabled_; }
  AssistantOnboardingMode onboarding_mode() const { return onboarding_mode_; }

 private:
  int consent_status_ = ConsentStatus::kUnknown;
  bool context_enabled_ = false;
  bool settings_enabled_ = false;
  bool hotword_always_on_ = false;
  bool hotword_enabled_ = false;
  bool launch_with_mic_open_ = false;
  bool notification_enabled_ = false;
  AssistantOnboardingMode onboarding_mode_ = AssistantOnboardingMode::kDefault;

  DISALLOW_COPY_AND_ASSIGN(TestAssistantStateObserver);
};

class AssistantStateControllerTest : public AshTestBase {
 protected:
  AssistantStateControllerTest() = default;
  ~AssistantStateControllerTest() override = default;

  // AshTestBase:
  void SetUp() override {
    AshTestBase::SetUp();

    prefs_ = Shell::Get()->session_controller()->GetPrimaryUserPrefService();
    DCHECK(prefs_);

    observer_ = std::make_unique<TestAssistantStateObserver>();
  }

  PrefService* prefs() { return prefs_; }

  TestAssistantStateObserver* observer() { return observer_.get(); }

 private:
  PrefService* prefs_ = nullptr;
  std::unique_ptr<TestAssistantStateObserver> observer_;

  DISALLOW_COPY_AND_ASSIGN(AssistantStateControllerTest);
};

}  // namespace

TEST_F(AssistantStateControllerTest, InitObserver) {
  prefs()->SetInteger(kAssistantConsentStatus,
                      ConsentStatus::kActivityControlAccepted);
  prefs()->SetBoolean(kAssistantContextEnabled, true);
  prefs()->SetBoolean(kAssistantEnabled, true);
  prefs()->SetBoolean(kAssistantHotwordAlwaysOn, true);
  prefs()->SetBoolean(kAssistantHotwordEnabled, true);
  prefs()->SetBoolean(kAssistantLaunchWithMicOpen, true);
  prefs()->SetBoolean(kAssistantNotificationEnabled, true);
  prefs()->SetString(kAssistantOnboardingMode, kAssistantOnboardingModeDefault);

  // The observer class should get an instant notification about the current
  // pref value.
  AssistantState::Get()->AddObserver(observer());
  EXPECT_EQ(observer()->consent_status(),
            ConsentStatus::kActivityControlAccepted);
  EXPECT_EQ(observer()->context_enabled(), true);
  EXPECT_EQ(observer()->settings_enabled(), true);
  EXPECT_EQ(observer()->hotword_always_on(), true);
  EXPECT_EQ(observer()->hotword_enabled(), true);
  EXPECT_EQ(observer()->launch_with_mic_open(), true);
  EXPECT_EQ(observer()->notification_enabled(), true);
  EXPECT_EQ(observer()->onboarding_mode(), AssistantOnboardingMode::kDefault);
  AssistantState::Get()->RemoveObserver(observer());
}

TEST_F(AssistantStateControllerTest, NotifyConsentStatus) {
  AssistantState::Get()->AddObserver(observer());

  prefs()->SetInteger(kAssistantConsentStatus, ConsentStatus::kUnauthorized);
  EXPECT_EQ(observer()->consent_status(), ConsentStatus::kUnauthorized);

  prefs()->SetInteger(kAssistantConsentStatus,
                      ConsentStatus::kActivityControlAccepted);
  EXPECT_EQ(observer()->consent_status(),
            ConsentStatus::kActivityControlAccepted);
  AssistantState::Get()->RemoveObserver(observer());
}

TEST_F(AssistantStateControllerTest, NotifyContextEnabled) {
  AssistantState::Get()->AddObserver(observer());

  prefs()->SetBoolean(kAssistantContextEnabled, false);
  EXPECT_EQ(observer()->context_enabled(), false);

  prefs()->SetBoolean(kAssistantContextEnabled, true);
  EXPECT_EQ(observer()->context_enabled(), true);
  AssistantState::Get()->RemoveObserver(observer());
}

TEST_F(AssistantStateControllerTest, NotifySettingsEnabled) {
  AssistantState::Get()->AddObserver(observer());

  prefs()->SetBoolean(kAssistantEnabled, false);
  EXPECT_EQ(observer()->settings_enabled(), false);

  prefs()->SetBoolean(kAssistantEnabled, true);
  EXPECT_EQ(observer()->settings_enabled(), true);
  AssistantState::Get()->RemoveObserver(observer());
}

TEST_F(AssistantStateControllerTest, NotifyHotwordAlwaysOn) {
  AssistantState::Get()->AddObserver(observer());

  prefs()->SetBoolean(kAssistantHotwordAlwaysOn, false);
  EXPECT_EQ(observer()->hotword_always_on(), false);

  prefs()->SetBoolean(kAssistantHotwordAlwaysOn, true);
  EXPECT_EQ(observer()->hotword_always_on(), true);
  AssistantState::Get()->RemoveObserver(observer());
}

TEST_F(AssistantStateControllerTest, NotifyHotwordEnabled) {
  AssistantState::Get()->AddObserver(observer());

  prefs()->SetBoolean(kAssistantHotwordEnabled, false);
  EXPECT_EQ(observer()->hotword_enabled(), false);

  prefs()->SetBoolean(kAssistantHotwordEnabled, true);
  EXPECT_EQ(observer()->hotword_enabled(), true);
  AssistantState::Get()->RemoveObserver(observer());
}

TEST_F(AssistantStateControllerTest, NotifyLaunchWithMicOpen) {
  AssistantState::Get()->AddObserver(observer());

  prefs()->SetBoolean(kAssistantLaunchWithMicOpen, false);
  EXPECT_EQ(observer()->launch_with_mic_open(), false);

  prefs()->SetBoolean(kAssistantLaunchWithMicOpen, true);
  EXPECT_EQ(observer()->launch_with_mic_open(), true);
  AssistantState::Get()->RemoveObserver(observer());
}

TEST_F(AssistantStateControllerTest, NotifyNotificationEnabled) {
  AssistantState::Get()->AddObserver(observer());

  prefs()->SetBoolean(kAssistantNotificationEnabled, false);
  EXPECT_EQ(observer()->notification_enabled(), false);

  prefs()->SetBoolean(kAssistantNotificationEnabled, true);
  EXPECT_EQ(observer()->notification_enabled(), true);
  AssistantState::Get()->RemoveObserver(observer());
}

TEST_F(AssistantStateControllerTest, NotifyOnboardingModeChanged) {
  AssistantState::Get()->AddObserver(observer());

  prefs()->SetString(kAssistantOnboardingMode, kAssistantOnboardingModeDefault);
  EXPECT_EQ(observer()->onboarding_mode(), AssistantOnboardingMode::kDefault);

  prefs()->SetString(kAssistantOnboardingMode,
                     kAssistantOnboardingModeEducation);
  EXPECT_EQ(observer()->onboarding_mode(), AssistantOnboardingMode::kEducation);
  AssistantState::Get()->RemoveObserver(observer());
}

}  // namespace ash
