// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/webui/settings/chromeos/settings_user_action_tracker.h"

#include "base/test/metrics/histogram_tester.h"
#include "base/values.h"
#include "chrome/browser/ui/webui/settings/chromeos/constants/setting.mojom.h"
#include "chrome/browser/ui/webui/settings/chromeos/fake_hierarchy.h"
#include "chrome/browser/ui/webui/settings/chromeos/fake_os_settings_section.h"
#include "chrome/browser/ui/webui/settings/chromeos/fake_os_settings_sections.h"
#include "chrome/browser/ui/webui/settings/chromeos/search/per_session_settings_user_action_tracker.h"
#include "chrome/browser/ui/webui/settings/chromeos/search/user_action_recorder.mojom.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace chromeos {
namespace settings {

class SettingsUserActionTrackerTest : public testing::Test {
 protected:
  SettingsUserActionTrackerTest()
      : fake_hierarchy_(&fake_sections_),
        tracker_(&fake_hierarchy_, &fake_sections_) {
    // Initialize per_session_tracker_ manually since BindInterface is never
    // called on tracker_.
    tracker_.per_session_tracker_ =
        std::make_unique<PerSessionSettingsUserActionTracker>();
  }
  ~SettingsUserActionTrackerTest() override = default;

  // testing::Test:
  void SetUp() override {
    fake_hierarchy_.AddSettingMetadata(mojom::Section::kBluetooth,
                                       mojom::Setting::kBluetoothOnOff);
    fake_hierarchy_.AddSettingMetadata(mojom::Section::kPeople,
                                       mojom::Setting::kAddAccount);
  }

  base::HistogramTester histogram_tester_;
  FakeOsSettingsSections fake_sections_;
  FakeHierarchy fake_hierarchy_;
  SettingsUserActionTracker tracker_;
};

TEST_F(SettingsUserActionTrackerTest, TestRecordSettingChangedBool) {
  // Record that the bluetooth enabled setting was toggled off.
  tracker_.RecordSettingChangeWithDetails(
      mojom::Setting::kBluetoothOnOff,
      mojom::SettingChangeValue::NewBoolValue(false));

  // The umbrella metric for which setting was changed should be updated. Note
  // that kBluetoothOnOff has enum value of 100.
  histogram_tester_.ExpectTotalCount("ChromeOS.Settings.SettingChanged",
                                     /*count=*/1);
  histogram_tester_.ExpectBucketCount("ChromeOS.Settings.SettingChanged",
                                      /*sample=*/100,
                                      /*count=*/1);

  // The LogMetric fn in the Blutooth section should have been called.
  const FakeOsSettingsSection* bluetooth_section =
      static_cast<const FakeOsSettingsSection*>(
          fake_sections_.GetSection(mojom::Section::kBluetooth));
  EXPECT_TRUE(bluetooth_section->logged_metrics().back() ==
              mojom::Setting::kBluetoothOnOff);
}

TEST_F(SettingsUserActionTrackerTest, TestRecordSettingChangedInt) {
  // Record that the user tried to add a 3rd account.
  tracker_.RecordSettingChangeWithDetails(
      mojom::Setting::kAddAccount, mojom::SettingChangeValue::NewIntValue(3));

  // The umbrella metric for which setting was changed should be updated. Note
  // that kAddAccount has enum value of 300.
  histogram_tester_.ExpectTotalCount("ChromeOS.Settings.SettingChanged",
                                     /*count=*/1);
  histogram_tester_.ExpectBucketCount("ChromeOS.Settings.SettingChanged",
                                      /*sample=*/300,
                                      /*count=*/1);

  // The LogMetric fn in the People section should have been called.
  const FakeOsSettingsSection* people_section =
      static_cast<const FakeOsSettingsSection*>(
          fake_sections_.GetSection(mojom::Section::kPeople));
  EXPECT_TRUE(people_section->logged_metrics().back() ==
              mojom::Setting::kAddAccount);
}

}  // namespace settings.
}  // namespace chromeos.
