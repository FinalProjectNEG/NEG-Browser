// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ash/system/phonehub/quick_actions_view.h"

#include "ash/system/phonehub/quick_action_item.h"
#include "ash/test/ash_test_base.h"
#include "base/test/scoped_feature_list.h"
#include "chromeos/components/phonehub/fake_phone_hub_manager.h"
#include "chromeos/constants/chromeos_features.h"

namespace ash {

using TetherController = chromeos::phonehub::TetherController;
using FindMyDeviceController = chromeos::phonehub::FindMyDeviceController;

namespace {

class DummyEvent : public ui::Event {
 public:
  DummyEvent() : Event(ui::ET_UNKNOWN, base::TimeTicks(), 0) {}
};

constexpr base::TimeDelta kWaitForRequestTimeout =
    base::TimeDelta::FromSeconds(10);

}  // namespace

class QuickActionsViewTest : public AshTestBase {
 public:
  QuickActionsViewTest()
      : AshTestBase(base::test::TaskEnvironment::TimeSource::MOCK_TIME) {}
  ~QuickActionsViewTest() override = default;

  // AshTestBase:
  void SetUp() override {
    feature_list_.InitAndEnableFeature(chromeos::features::kPhoneHub);
    AshTestBase::SetUp();

    quick_actions_view_ =
        std::make_unique<QuickActionsView>(&phone_hub_manager_);
  }

  void TearDown() override {
    quick_actions_view_.reset();
    AshTestBase::TearDown();
  }

 protected:
  QuickActionsView* actions_view() { return quick_actions_view_.get(); }
  chromeos::phonehub::FakeTetherController* tether_controller() {
    return phone_hub_manager_.fake_tether_controller();
  }
  chromeos::phonehub::FakeDoNotDisturbController* dnd_controller() {
    return phone_hub_manager_.fake_do_not_disturb_controller();
  }
  chromeos::phonehub::FakeFindMyDeviceController* find_my_device_controller() {
    return phone_hub_manager_.fake_find_my_device_controller();
  }

 private:
  std::unique_ptr<QuickActionsView> quick_actions_view_;
  chromeos::phonehub::FakePhoneHubManager phone_hub_manager_;
  base::test::ScopedFeatureList feature_list_;
};

TEST_F(QuickActionsViewTest, EnableHotspotVisibility) {
  tether_controller()->SetStatus(
      TetherController::Status::kIneligibleForFeature);

  // Enable Hotspot button should not be shown if the feature is ineligible.
  EXPECT_FALSE(actions_view()->enable_hotspot_for_testing()->GetVisible());

  tether_controller()->SetStatus(
      TetherController::Status::kConnectionAvailable);
  // Enable Hotspot button should be shown if the feature is available.
  EXPECT_TRUE(actions_view()->enable_hotspot_for_testing()->GetVisible());
}

TEST_F(QuickActionsViewTest, EnableHotspotToggle) {
  tether_controller()->SetStatus(
      TetherController::Status::kConnectionAvailable);

  // Simulate a toggle press. Status should be connecting.
  actions_view()->enable_hotspot_for_testing()->ButtonPressed(nullptr,
                                                              DummyEvent());
  EXPECT_EQ(TetherController::Status::kConnecting,
            tether_controller()->GetStatus());

  tether_controller()->SetStatus(TetherController::Status::kConnected);
  // Toggle again will change the state.
  actions_view()->enable_hotspot_for_testing()->ButtonPressed(nullptr,
                                                              DummyEvent());
  EXPECT_EQ(TetherController::Status::kConnecting,
            tether_controller()->GetStatus());
}

TEST_F(QuickActionsViewTest, SilencePhoneToggle) {
  // Initially, silence phone is not enabled.
  EXPECT_FALSE(dnd_controller()->IsDndEnabled());

  // Toggle the button will enable the feature.
  actions_view()->silence_phone_for_testing()->ButtonPressed(nullptr,
                                                             DummyEvent());
  EXPECT_TRUE(dnd_controller()->IsDndEnabled());

  // Togge again to disable.
  actions_view()->silence_phone_for_testing()->ButtonPressed(nullptr,
                                                             DummyEvent());
  EXPECT_FALSE(dnd_controller()->IsDndEnabled());

  // Test the error state.
  dnd_controller()->SetShouldRequestFail(true);
  actions_view()->silence_phone_for_testing()->ButtonPressed(nullptr,
                                                             DummyEvent());

  // In error state, do not disturb is disabled but the button should still be
  // on after being pressed.
  EXPECT_FALSE(dnd_controller()->IsDndEnabled());
  EXPECT_TRUE(actions_view()->silence_phone_for_testing()->IsToggled());

  // After a certain time, the button should be corrected to be off.
  task_environment()->FastForwardBy(kWaitForRequestTimeout);
  EXPECT_FALSE(actions_view()->silence_phone_for_testing()->IsToggled());

  dnd_controller()->SetShouldRequestFail(false);
}

TEST_F(QuickActionsViewTest, LocatePhoneToggle) {
  // Initially, locate phone is not enabled.
  EXPECT_EQ(FindMyDeviceController::Status::kRingingOff,
            find_my_device_controller()->GetPhoneRingingStatus());

  // Toggle the button will enable the feature.
  actions_view()->locate_phone_for_testing()->ButtonPressed(nullptr,
                                                            DummyEvent());
  EXPECT_EQ(FindMyDeviceController::Status::kRingingOn,
            find_my_device_controller()->GetPhoneRingingStatus());

  // Togge again to disable.
  actions_view()->locate_phone_for_testing()->ButtonPressed(nullptr,
                                                            DummyEvent());
  EXPECT_EQ(FindMyDeviceController::Status::kRingingOff,
            find_my_device_controller()->GetPhoneRingingStatus());

  // Test the error state.
  find_my_device_controller()->SetShouldRequestFail(true);
  actions_view()->locate_phone_for_testing()->ButtonPressed(nullptr,
                                                            DummyEvent());

  // In error state, find my device is disabled but the button should still be
  // on after being pressed.
  EXPECT_EQ(FindMyDeviceController::Status::kRingingOff,
            find_my_device_controller()->GetPhoneRingingStatus());
  EXPECT_TRUE(actions_view()->locate_phone_for_testing()->IsToggled());

  // After a certain time, the button should be corrected to be off.
  task_environment()->FastForwardBy(kWaitForRequestTimeout);
  EXPECT_FALSE(actions_view()->locate_phone_for_testing()->IsToggled());

  find_my_device_controller()->SetShouldRequestFail(false);
}

}  // namespace ash
