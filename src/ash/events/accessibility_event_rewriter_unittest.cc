// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ash/events/accessibility_event_rewriter.h"

#include <memory>
#include <vector>

#include "ash/accessibility/accessibility_controller_impl.h"
#include "ash/public/cpp/accessibility_event_rewriter_delegate.h"
#include "ash/shell.h"
#include "ash/test/ash_test_base.h"
#include "base/macros.h"
#include "ui/aura/env.h"
#include "ui/aura/window.h"
#include "ui/aura/window_tree_host.h"
#include "ui/chromeos/events/event_rewriter_chromeos.h"
#include "ui/chromeos/events/modifier_key.h"
#include "ui/chromeos/events/pref_names.h"
#include "ui/events/devices/device_data_manager_test_api.h"
#include "ui/events/event.h"
#include "ui/events/event_constants.h"
#include "ui/events/event_handler.h"
#include "ui/events/event_rewriter.h"
#include "ui/events/keycodes/keyboard_codes.h"
#include "ui/events/test/event_generator.h"
#include "ui/events/test/test_event_rewriter.h"
#include "ui/events/types/event_type.h"

namespace ash {
namespace {

// A test implementation of the spoken feedback delegate interface.
// TODO(crbug/1116205): Merge ChromeVox and Switch Access test infrastructure
// below.
class ChromeVoxTestDelegate : public AccessibilityEventRewriterDelegate {
 public:
  ChromeVoxTestDelegate() = default;
  ChromeVoxTestDelegate(const ChromeVoxTestDelegate&) = delete;
  ChromeVoxTestDelegate& operator=(const ChromeVoxTestDelegate&) = delete;
  ~ChromeVoxTestDelegate() override = default;

  // Count of events sent to the delegate.
  size_t chromevox_recorded_event_count_ = 0;

  // Count of captured events sent to the delegate.
  size_t chromevox_captured_event_count_ = 0;

 private:
  // AccessibilityEventRewriterDelegate:
  void DispatchKeyEventToChromeVox(std::unique_ptr<ui::Event> event,
                                   bool capture) override {
    chromevox_recorded_event_count_++;
    if (capture)
      chromevox_captured_event_count_++;
  }
  void DispatchMouseEventToChromeVox(
      std::unique_ptr<ui::Event> event) override {
    chromevox_recorded_event_count_++;
  }
  void SendSwitchAccessCommand(SwitchAccessCommand command) override {}
};

class ChromeVoxAccessibilityEventRewriterTest
    : public ash::AshTestBase,
      public ui::EventRewriterChromeOS::Delegate {
 public:
  ChromeVoxAccessibilityEventRewriterTest() {
    event_rewriter_chromeos_ =
        std::make_unique<ui::EventRewriterChromeOS>(this, nullptr, false);
  }
  ChromeVoxAccessibilityEventRewriterTest(
      const ChromeVoxAccessibilityEventRewriterTest&) = delete;
  ChromeVoxAccessibilityEventRewriterTest& operator=(
      const ChromeVoxAccessibilityEventRewriterTest&) = delete;

  void SetUp() override {
    ash::AshTestBase::SetUp();
    generator_ = AshTestBase::GetEventGenerator();
    accessibility_event_rewriter_ =
        std::make_unique<AccessibilityEventRewriter>(
            event_rewriter_chromeos_.get(), &delegate_);
    GetContext()->GetHost()->GetEventSource()->AddEventRewriter(
        accessibility_event_rewriter_.get());
    GetContext()->GetHost()->GetEventSource()->AddEventRewriter(
        &event_recorder_);
  }

  void TearDown() override {
    GetContext()->GetHost()->GetEventSource()->RemoveEventRewriter(
        &event_recorder_);
    GetContext()->GetHost()->GetEventSource()->RemoveEventRewriter(
        accessibility_event_rewriter_.get());
    accessibility_event_rewriter_.reset();
    generator_ = nullptr;
    ash::AshTestBase::TearDown();
  }

  size_t delegate_chromevox_recorded_event_count() {
    return delegate_.chromevox_recorded_event_count_;
  }

  size_t delegate_chromevox_captured_event_count() {
    return delegate_.chromevox_captured_event_count_;
  }

  void SetDelegateChromeVoxCaptureAllKeys(bool value) {
    accessibility_event_rewriter_->set_chromevox_capture_all_keys(value);
  }

  void ExpectCounts(size_t expected_recorded_count,
                    size_t expected_delegate_count,
                    size_t expected_captured_count) {
    EXPECT_EQ(expected_recorded_count,
              static_cast<size_t>(event_recorder_.events_seen()));
    EXPECT_EQ(expected_delegate_count,
              delegate_chromevox_recorded_event_count());
    EXPECT_EQ(expected_captured_count,
              delegate_chromevox_captured_event_count());
  }

  void SetModifierRemapping(const std::string& pref_name,
                            ui::chromeos::ModifierKey value) {
    modifier_remapping_[pref_name] = static_cast<int>(value);
  }

  std::set<int> GetSwitchAccessKeyCodesToCapture() {
    return accessibility_event_rewriter_
        ->switch_access_key_codes_to_capture_for_test();
  }

  std::map<int, SwitchAccessCommand> GetSwitchAccessCommandForKeyCodeMap() {
    return accessibility_event_rewriter_
        ->key_code_to_switch_access_command_map_for_test();
  }

 protected:
  // A test accessibility event delegate; simulates ChromeVox and Switch Access.
  ChromeVoxTestDelegate delegate_;
  // Generates ui::Events from simulated user input.
  ui::test::EventGenerator* generator_ = nullptr;
  // Records events delivered to the next event rewriter after spoken feedback.
  ui::test::TestEventRewriter event_recorder_;

  std::unique_ptr<AccessibilityEventRewriter> accessibility_event_rewriter_;

  std::unique_ptr<ui::EventRewriterChromeOS> event_rewriter_chromeos_;

 private:
  // ui::EventRewriterChromeOS::Delegate:
  bool RewriteModifierKeys() override { return true; }

  bool GetKeyboardRemappedPrefValue(const std::string& pref_name,
                                    int* value) const override {
    auto it = modifier_remapping_.find(pref_name);
    if (it == modifier_remapping_.end())
      return false;

    *value = it->second;
    return true;
  }

  bool TopRowKeysAreFunctionKeys() const override { return false; }

  bool IsExtensionCommandRegistered(ui::KeyboardCode key_code,
                                    int flags) const override {
    return false;
  }

  bool IsSearchKeyAcceleratorReserved() const override { return false; }

  std::map<std::string, int> modifier_remapping_;
};

// The delegate should not intercept events when spoken feedback is disabled.
TEST_F(ChromeVoxAccessibilityEventRewriterTest, EventsNotConsumedWhenDisabled) {
  AccessibilityControllerImpl* controller =
      Shell::Get()->accessibility_controller();
  EXPECT_FALSE(controller->spoken_feedback().enabled());

  generator_->PressKey(ui::VKEY_A, ui::EF_NONE);
  EXPECT_EQ(1, event_recorder_.events_seen());
  EXPECT_EQ(0U, delegate_chromevox_recorded_event_count());
  generator_->ReleaseKey(ui::VKEY_A, ui::EF_NONE);
  EXPECT_EQ(2, event_recorder_.events_seen());
  EXPECT_EQ(0U, delegate_chromevox_recorded_event_count());

  generator_->ClickLeftButton();
  EXPECT_EQ(4, event_recorder_.events_seen());
  EXPECT_EQ(0U, delegate_chromevox_recorded_event_count());

  generator_->GestureTapAt(gfx::Point());
  EXPECT_EQ(6, event_recorder_.events_seen());
  EXPECT_EQ(0U, delegate_chromevox_recorded_event_count());
}

// The delegate should intercept key events when spoken feedback is enabled.
TEST_F(ChromeVoxAccessibilityEventRewriterTest, KeyEventsConsumedWhenEnabled) {
  AccessibilityControllerImpl* controller =
      Shell::Get()->accessibility_controller();
  controller->SetSpokenFeedbackEnabled(true, A11Y_NOTIFICATION_NONE);
  EXPECT_TRUE(controller->spoken_feedback().enabled());

  generator_->PressKey(ui::VKEY_A, ui::EF_NONE);
  EXPECT_EQ(1, event_recorder_.events_seen());
  EXPECT_EQ(1U, delegate_chromevox_recorded_event_count());
  EXPECT_EQ(0U, delegate_chromevox_captured_event_count());
  generator_->ReleaseKey(ui::VKEY_A, ui::EF_NONE);
  EXPECT_EQ(2, event_recorder_.events_seen());
  EXPECT_EQ(2U, delegate_chromevox_recorded_event_count());
  EXPECT_EQ(0U, delegate_chromevox_captured_event_count());

  generator_->ClickLeftButton();
  EXPECT_EQ(4, event_recorder_.events_seen());
  EXPECT_EQ(2U, delegate_chromevox_recorded_event_count());
  EXPECT_EQ(0U, delegate_chromevox_captured_event_count());

  generator_->GestureTapAt(gfx::Point());
  EXPECT_EQ(6, event_recorder_.events_seen());
  EXPECT_EQ(2U, delegate_chromevox_recorded_event_count());
  EXPECT_EQ(0U, delegate_chromevox_captured_event_count());
}

// Asynchronously unhandled events should be sent to subsequent rewriters.
TEST_F(ChromeVoxAccessibilityEventRewriterTest,
       UnhandledEventsSentToOtherRewriters) {
  // Before it can forward unhandled events, AccessibilityEventRewriter
  // must have seen at least one event in the first place.
  generator_->PressKey(ui::VKEY_A, ui::EF_NONE);
  EXPECT_EQ(1, event_recorder_.events_seen());
  generator_->ReleaseKey(ui::VKEY_A, ui::EF_NONE);
  EXPECT_EQ(2, event_recorder_.events_seen());

  accessibility_event_rewriter_->OnUnhandledSpokenFeedbackEvent(
      std::make_unique<ui::KeyEvent>(ui::ET_KEY_PRESSED, ui::VKEY_A,
                                     ui::EF_NONE));
  EXPECT_EQ(3, event_recorder_.events_seen());
  accessibility_event_rewriter_->OnUnhandledSpokenFeedbackEvent(
      std::make_unique<ui::KeyEvent>(ui::ET_KEY_RELEASED, ui::VKEY_A,
                                     ui::EF_NONE));
  EXPECT_EQ(4, event_recorder_.events_seen());
}

TEST_F(ChromeVoxAccessibilityEventRewriterTest,
       KeysNotEatenWithChromeVoxDisabled) {
  AccessibilityControllerImpl* controller =
      Shell::Get()->accessibility_controller();
  EXPECT_FALSE(controller->spoken_feedback().enabled());

  // Send Search+Shift+Right.
  generator_->PressKey(ui::VKEY_LWIN, ui::EF_COMMAND_DOWN);
  EXPECT_EQ(1, event_recorder_.events_seen());
  generator_->PressKey(ui::VKEY_SHIFT, ui::EF_COMMAND_DOWN | ui::EF_SHIFT_DOWN);
  EXPECT_EQ(2, event_recorder_.events_seen());

  // Mock successful commands lookup and dispatch; shouldn't matter either way.
  generator_->PressKey(ui::VKEY_RIGHT, ui::EF_COMMAND_DOWN | ui::EF_SHIFT_DOWN);
  EXPECT_EQ(3, event_recorder_.events_seen());

  // Released keys shouldn't get eaten.
  generator_->ReleaseKey(ui::VKEY_RIGHT,
                         ui::EF_COMMAND_DOWN | ui::EF_SHIFT_DOWN);
  generator_->ReleaseKey(ui::VKEY_SHIFT, ui::EF_COMMAND_DOWN);
  generator_->ReleaseKey(ui::VKEY_LWIN, 0);
  EXPECT_EQ(6, event_recorder_.events_seen());

  // Try releasing more keys.
  generator_->ReleaseKey(ui::VKEY_RIGHT, 0);
  generator_->ReleaseKey(ui::VKEY_SHIFT, 0);
  generator_->ReleaseKey(ui::VKEY_LWIN, 0);
  EXPECT_EQ(9, event_recorder_.events_seen());

  EXPECT_EQ(0U, delegate_chromevox_recorded_event_count());
}

TEST_F(ChromeVoxAccessibilityEventRewriterTest, KeyEventsCaptured) {
  AccessibilityControllerImpl* controller =
      Shell::Get()->accessibility_controller();
  controller->SetSpokenFeedbackEnabled(true, A11Y_NOTIFICATION_NONE);
  EXPECT_TRUE(controller->spoken_feedback().enabled());

  // Initialize expected counts as variables for easier maintaiblity.
  size_t recorded_count = 0;
  size_t delegate_count = 0;
  size_t captured_count = 0;

  // Anything with Search gets captured.
  generator_->PressKey(ui::VKEY_LWIN, ui::EF_COMMAND_DOWN);
  ExpectCounts(recorded_count, ++delegate_count, ++captured_count);
  generator_->ReleaseKey(ui::VKEY_LWIN, ui::EF_COMMAND_DOWN);
  ExpectCounts(recorded_count, ++delegate_count, ++captured_count);

  // Tab never gets captured.
  generator_->PressKey(ui::VKEY_TAB, ui::EF_NONE);
  ExpectCounts(++recorded_count, ++delegate_count, captured_count);
  generator_->ReleaseKey(ui::VKEY_TAB, ui::EF_NONE);
  ExpectCounts(++recorded_count, ++delegate_count, captured_count);

  // A client requested capture of all keys.
  SetDelegateChromeVoxCaptureAllKeys(true);
  generator_->PressKey(ui::VKEY_A, ui::EF_NONE);
  ExpectCounts(recorded_count, ++delegate_count, ++captured_count);
  generator_->ReleaseKey(ui::VKEY_A, ui::EF_NONE);
  ExpectCounts(recorded_count, ++delegate_count, ++captured_count);

  // Tab never gets captured even with explicit client request for all keys.
  generator_->PressKey(ui::VKEY_TAB, ui::EF_NONE);
  ExpectCounts(++recorded_count, ++delegate_count, captured_count);
  generator_->ReleaseKey(ui::VKEY_TAB, ui::EF_NONE);
  ExpectCounts(++recorded_count, ++delegate_count, captured_count);

  // A client requested to not capture all keys.
  SetDelegateChromeVoxCaptureAllKeys(false);
  generator_->PressKey(ui::VKEY_A, ui::EF_NONE);
  ExpectCounts(++recorded_count, ++delegate_count, captured_count);
  generator_->ReleaseKey(ui::VKEY_A, ui::EF_NONE);
  ExpectCounts(++recorded_count, ++delegate_count, captured_count);
}

TEST_F(ChromeVoxAccessibilityEventRewriterTest,
       KeyEventsCapturedWithModifierRemapping) {
  AccessibilityControllerImpl* controller =
      Shell::Get()->accessibility_controller();
  controller->SetSpokenFeedbackEnabled(true, A11Y_NOTIFICATION_NONE);
  EXPECT_TRUE(controller->spoken_feedback().enabled());

  // Initialize expected counts as variables for easier maintaiblity.
  size_t recorded_count = 0;
  size_t delegate_count = 0;
  size_t captured_count = 0;

  // Map Control key to Search.
  SetModifierRemapping(prefs::kLanguageRemapControlKeyTo,
                       ui::chromeos::ModifierKey::kSearchKey);

  // Anything with Search gets captured.
  generator_->PressKey(ui::VKEY_CONTROL, ui::EF_CONTROL_DOWN);
  ExpectCounts(recorded_count, ++delegate_count, ++captured_count);
  // EventRewriterChromeOS actually omits the modifier flag.
  generator_->ReleaseKey(ui::VKEY_CONTROL, 0);
  ExpectCounts(recorded_count, ++delegate_count, ++captured_count);

  // Search itself should also work.
  generator_->PressKey(ui::VKEY_LWIN, ui::EF_COMMAND_DOWN);
  ExpectCounts(recorded_count, ++delegate_count, ++captured_count);
  generator_->ReleaseKey(ui::VKEY_LWIN, 0);
  ExpectCounts(recorded_count, ++delegate_count, ++captured_count);

  // Remapping should have no effect on all other expectations.

  // Tab never gets captured.
  generator_->PressKey(ui::VKEY_TAB, ui::EF_NONE);
  ExpectCounts(++recorded_count, ++delegate_count, captured_count);
  generator_->ReleaseKey(ui::VKEY_TAB, ui::EF_NONE);
  ExpectCounts(++recorded_count, ++delegate_count, captured_count);

  // A client requested capture of all keys.
  SetDelegateChromeVoxCaptureAllKeys(true);
  generator_->PressKey(ui::VKEY_A, ui::EF_NONE);
  ExpectCounts(recorded_count, ++delegate_count, ++captured_count);
  generator_->ReleaseKey(ui::VKEY_A, ui::EF_NONE);
  ExpectCounts(recorded_count, ++delegate_count, ++captured_count);

  // Tab never gets captured even with explicit client request for all keys.
  generator_->PressKey(ui::VKEY_TAB, ui::EF_NONE);
  ExpectCounts(++recorded_count, ++delegate_count, captured_count);
  generator_->ReleaseKey(ui::VKEY_TAB, ui::EF_NONE);
  ExpectCounts(++recorded_count, ++delegate_count, captured_count);

  // A client requested to not capture all keys.
  SetDelegateChromeVoxCaptureAllKeys(false);
  generator_->PressKey(ui::VKEY_A, ui::EF_NONE);
  ExpectCounts(++recorded_count, ++delegate_count, captured_count);
  generator_->ReleaseKey(ui::VKEY_A, ui::EF_NONE);
  ExpectCounts(++recorded_count, ++delegate_count, captured_count);
}

// Records all key events for testing.
class EventCapturer : public ui::EventHandler {
 public:
  EventCapturer() = default;
  ~EventCapturer() override = default;

  void Reset() { last_key_event_.reset(); }

  ui::KeyEvent* last_key_event() { return last_key_event_.get(); }

 private:
  void OnKeyEvent(ui::KeyEvent* event) override {
    last_key_event_ = std::make_unique<ui::KeyEvent>(*event);
  }

  std::unique_ptr<ui::KeyEvent> last_key_event_;

  DISALLOW_COPY_AND_ASSIGN(EventCapturer);
};

class SwitchAccessTestDelegate : public AccessibilityEventRewriterDelegate {
 public:
  SwitchAccessTestDelegate() = default;
  ~SwitchAccessTestDelegate() override = default;

  SwitchAccessCommand last_command() { return commands_.back(); }
  int command_count() { return commands_.size(); }

  // AccessibilityEventRewriterDelegate:
  void SendSwitchAccessCommand(SwitchAccessCommand command) override {
    commands_.push_back(command);
  }
  void DispatchKeyEventToChromeVox(std::unique_ptr<ui::Event>, bool) override {}
  void DispatchMouseEventToChromeVox(std::unique_ptr<ui::Event>) override {}

 private:
  std::vector<SwitchAccessCommand> commands_;

  DISALLOW_COPY_AND_ASSIGN(SwitchAccessTestDelegate);
};

class SwitchAccessAccessibilityEventRewriterTest : public AshTestBase {
 public:
  SwitchAccessAccessibilityEventRewriterTest() {
    event_rewriter_chromeos_ =
        std::make_unique<ui::EventRewriterChromeOS>(nullptr, nullptr, false);
  }
  ~SwitchAccessAccessibilityEventRewriterTest() override = default;

  void SetUp() override {
    AshTestBase::SetUp();

    // This test triggers a resize of WindowTreeHost, which will end up
    // throttling events. set_throttle_input_on_resize_for_testing() disables
    // this.
    aura::Env::GetInstance()->set_throttle_input_on_resize_for_testing(false);

    delegate_ = std::make_unique<SwitchAccessTestDelegate>();
    accessibility_event_rewriter_ =
        std::make_unique<AccessibilityEventRewriter>(
            event_rewriter_chromeos_.get(), delegate_.get());
    generator_ = AshTestBase::GetEventGenerator();
    GetContext()->AddPreTargetHandler(&event_capturer_);

    GetContext()->GetHost()->GetEventSource()->AddEventRewriter(
        accessibility_event_rewriter_.get());

    controller_ = Shell::Get()->accessibility_controller();
    controller_->SetAccessibilityEventRewriter(
        accessibility_event_rewriter_.get());
    controller_->switch_access().SetEnabled(true);
  }

  void TearDown() override {
    GetContext()->RemovePreTargetHandler(&event_capturer_);
    generator_ = nullptr;
    controller_ = nullptr;
    accessibility_event_rewriter_.reset();
    AshTestBase::TearDown();
  }

  void SetKeyCodesForSwitchAccessCommand(std::set<int> key_codes,
                                         SwitchAccessCommand command) {
    AccessibilityEventRewriter* rewriter =
        controller_->GetAccessibilityEventRewriterForTest();
    rewriter->SetKeyCodesForSwitchAccessCommand(key_codes, command);
  }

  const std::set<int> GetKeyCodesToCapture() {
    AccessibilityEventRewriter* rewriter =
        controller_->GetAccessibilityEventRewriterForTest();
    if (rewriter)
      return rewriter->switch_access_key_codes_to_capture_for_test();
    return std::set<int>();
  }

  const std::map<int, SwitchAccessCommand> GetCommandForKeyCodeMap() {
    AccessibilityEventRewriter* rewriter =
        controller_->GetAccessibilityEventRewriterForTest();
    if (rewriter)
      return rewriter->key_code_to_switch_access_command_map_for_test();
    return std::map<int, SwitchAccessCommand>();
  }

 protected:
  ui::test::EventGenerator* generator_ = nullptr;
  EventCapturer event_capturer_;
  AccessibilityControllerImpl* controller_ = nullptr;
  std::unique_ptr<SwitchAccessTestDelegate> delegate_;
  std::unique_ptr<AccessibilityEventRewriter> accessibility_event_rewriter_;
  std::unique_ptr<ui::EventRewriterChromeOS> event_rewriter_chromeos_;
};

TEST_F(SwitchAccessAccessibilityEventRewriterTest, CaptureSpecifiedKeys) {
  // Set keys for Switch Access to capture.
  SetKeyCodesForSwitchAccessCommand({ui::VKEY_1, ui::VKEY_2},
                                    SwitchAccessCommand::kSelect);

  EXPECT_FALSE(event_capturer_.last_key_event());

  generator_->PressKey(ui::VKEY_1, ui::EF_NONE);
  generator_->ReleaseKey(ui::VKEY_1, ui::EF_NONE);

  // The event was captured by AccessibilityEventRewriter.
  EXPECT_FALSE(event_capturer_.last_key_event());
  EXPECT_EQ(SwitchAccessCommand::kSelect, delegate_->last_command());

  // Press the "2" key.
  generator_->PressKey(ui::VKEY_2, ui::EF_NONE);
  generator_->ReleaseKey(ui::VKEY_2, ui::EF_NONE);

  // We received a new event.

  // The event was captured by AccessibilityEventRewriter.
  EXPECT_FALSE(event_capturer_.last_key_event());

  // Press the "3" key.
  generator_->PressKey(ui::VKEY_3, ui::EF_NONE);
  generator_->ReleaseKey(ui::VKEY_3, ui::EF_NONE);

  // The event was captured by AccessibilityEventRewriter.
  EXPECT_TRUE(event_capturer_.last_key_event());
}

TEST_F(SwitchAccessAccessibilityEventRewriterTest,
       KeysNoLongerCaptureAfterUpdate) {
  // Set Switch Access to capture the keys {1, 2, 3}.
  SetKeyCodesForSwitchAccessCommand({ui::VKEY_1, ui::VKEY_2, ui::VKEY_3},
                                    SwitchAccessCommand::kSelect);

  EXPECT_FALSE(event_capturer_.last_key_event());

  // Press the "1" key.
  generator_->PressKey(ui::VKEY_1, ui::EF_NONE);
  generator_->ReleaseKey(ui::VKEY_1, ui::EF_NONE);

  // The event was captured by AccessibilityEventRewriter.
  EXPECT_FALSE(event_capturer_.last_key_event());
  EXPECT_EQ(SwitchAccessCommand::kSelect, delegate_->last_command());

  // Update the Switch Access keys to capture {2, 3, 4}.
  SetKeyCodesForSwitchAccessCommand({ui::VKEY_2, ui::VKEY_3, ui::VKEY_4},
                                    SwitchAccessCommand::kSelect);

  // Press the "1" key.
  generator_->PressKey(ui::VKEY_1, ui::EF_NONE);
  generator_->ReleaseKey(ui::VKEY_1, ui::EF_NONE);

  // We received a new event.

  // The event was NOT captured by AccessibilityEventRewriter.
  EXPECT_TRUE(event_capturer_.last_key_event());
  EXPECT_FALSE(event_capturer_.last_key_event()->handled());

  // Press the "4" key.
  generator_->PressKey(ui::VKEY_4, ui::EF_NONE);
  generator_->ReleaseKey(ui::VKEY_4, ui::EF_NONE);

  // The event was captured by AccessibilityEventRewriter.
}

TEST_F(SwitchAccessAccessibilityEventRewriterTest,
       SetKeyCodesForSwitchAccessCommand) {
  AccessibilityEventRewriter* rewriter =
      controller_->GetAccessibilityEventRewriterForTest();
  EXPECT_NE(nullptr, rewriter);

  // Both the key codes to capture and the command map should be empty.
  EXPECT_EQ(0u, GetKeyCodesToCapture().size());
  EXPECT_EQ(0u, GetCommandForKeyCodeMap().size());

  // Set key codes for Select command.
  std::set<int> new_key_codes;
  new_key_codes.insert(48 /* '0' */);
  new_key_codes.insert(83 /* 's' */);
  rewriter->SetKeyCodesForSwitchAccessCommand(new_key_codes,
                                              SwitchAccessCommand::kSelect);

  // Check that values are added to both data structures.
  std::set<int> kc_to_capture = GetKeyCodesToCapture();
  EXPECT_EQ(2u, kc_to_capture.size());
  EXPECT_EQ(1u, kc_to_capture.count(48));
  EXPECT_EQ(1u, kc_to_capture.count(83));

  std::map<int, SwitchAccessCommand> command_map = GetCommandForKeyCodeMap();
  EXPECT_EQ(2u, command_map.size());
  EXPECT_EQ(SwitchAccessCommand::kSelect, command_map.at(48));
  EXPECT_EQ(SwitchAccessCommand::kSelect, command_map.at(83));

  // Set key codes for the Next command.
  new_key_codes.clear();
  new_key_codes.insert(49 /* '1' */);
  new_key_codes.insert(78 /* 'n' */);
  rewriter->SetKeyCodesForSwitchAccessCommand(new_key_codes,
                                              SwitchAccessCommand::kNext);

  // Check that the new values are added and old values are not changed.
  kc_to_capture = GetKeyCodesToCapture();
  EXPECT_EQ(4u, kc_to_capture.size());
  EXPECT_EQ(1u, kc_to_capture.count(49));
  EXPECT_EQ(1u, kc_to_capture.count(78));

  command_map = GetCommandForKeyCodeMap();
  EXPECT_EQ(4u, command_map.size());
  EXPECT_EQ(SwitchAccessCommand::kNext, command_map.at(49));
  EXPECT_EQ(SwitchAccessCommand::kNext, command_map.at(78));

  // Set key codes for the Previous command. Re-use a key code from above.
  new_key_codes.clear();
  new_key_codes.insert(49 /* '1' */);
  new_key_codes.insert(80 /* 'p' */);
  rewriter->SetKeyCodesForSwitchAccessCommand(new_key_codes,
                                              SwitchAccessCommand::kPrevious);

  // Check that '1' has been remapped to Previous.
  kc_to_capture = GetKeyCodesToCapture();
  EXPECT_EQ(5u, kc_to_capture.size());
  EXPECT_EQ(1u, kc_to_capture.count(49));
  EXPECT_EQ(1u, kc_to_capture.count(80));

  command_map = GetCommandForKeyCodeMap();
  EXPECT_EQ(5u, command_map.size());
  EXPECT_EQ(SwitchAccessCommand::kPrevious, command_map.at(49));
  EXPECT_EQ(SwitchAccessCommand::kPrevious, command_map.at(80));
  EXPECT_EQ(SwitchAccessCommand::kNext, command_map.at(78));

  // Set a new key code for the Select command.
  new_key_codes.clear();
  new_key_codes.insert(51 /* '3' */);
  new_key_codes.insert(83 /* 's' */);
  rewriter->SetKeyCodesForSwitchAccessCommand(new_key_codes,
                                              SwitchAccessCommand::kSelect);

  // Check that the previously set values for Select have been cleared.
  kc_to_capture = GetKeyCodesToCapture();
  EXPECT_EQ(5u, kc_to_capture.size());
  EXPECT_EQ(0u, kc_to_capture.count(48));
  EXPECT_EQ(1u, kc_to_capture.count(51));
  EXPECT_EQ(1u, kc_to_capture.count(83));

  command_map = GetCommandForKeyCodeMap();
  EXPECT_EQ(5u, command_map.size());
  EXPECT_EQ(SwitchAccessCommand::kSelect, command_map.at(51));
  EXPECT_EQ(SwitchAccessCommand::kSelect, command_map.at(83));
  EXPECT_EQ(command_map.end(), command_map.find(48));
}

TEST_F(SwitchAccessAccessibilityEventRewriterTest, SetKeyboardInputTypes) {
  AccessibilityEventRewriter* rewriter =
      controller_->GetAccessibilityEventRewriterForTest();
  EXPECT_NE(nullptr, rewriter);

  // Set Switch Access to capture these keys as the select command.
  SetKeyCodesForSwitchAccessCommand(
      {ui::VKEY_1, ui::VKEY_2, ui::VKEY_3, ui::VKEY_4},
      SwitchAccessCommand::kSelect);

  std::vector<ui::InputDevice> keyboards;
  ui::DeviceDataManagerTestApi device_data_test_api;
  keyboards.emplace_back(ui::InputDevice(1, ui::INPUT_DEVICE_INTERNAL, ""));
  keyboards.emplace_back(ui::InputDevice(2, ui::INPUT_DEVICE_USB, ""));
  keyboards.emplace_back(ui::InputDevice(3, ui::INPUT_DEVICE_BLUETOOTH, ""));
  keyboards.emplace_back(ui::InputDevice(4, ui::INPUT_DEVICE_UNKNOWN, ""));
  device_data_test_api.SetKeyboardDevices(keyboards);

  // Press the "1" key with no source device id.
  generator_->PressKey(ui::VKEY_1, ui::EF_NONE);
  generator_->ReleaseKey(ui::VKEY_1, ui::EF_NONE);

  // The event was captured by AccessibilityEventRewriter.
  EXPECT_FALSE(event_capturer_.last_key_event());
  EXPECT_EQ(SwitchAccessCommand::kSelect, delegate_->last_command());

  // Press the "1" key from the internal keyboard which is captured by
  // AccessibilityEventRewriter.
  generator_->PressKey(ui::VKEY_1, ui::EF_NONE, 1);
  generator_->ReleaseKey(ui::VKEY_1, ui::EF_NONE, 1);
  EXPECT_FALSE(event_capturer_.last_key_event());

  // Press the "2" key from the usb keyboard which is captured by
  // AccessibilityEventRewriter.
  generator_->PressKey(ui::VKEY_2, ui::EF_NONE, 2);
  generator_->ReleaseKey(ui::VKEY_2, ui::EF_NONE, 2);
  EXPECT_FALSE(event_capturer_.last_key_event());

  // Press the "3" key from the bluetooth keyboard which is captured by
  // AccessibilityEventRewriter.
  generator_->PressKey(ui::VKEY_3, ui::EF_NONE, 3);
  generator_->ReleaseKey(ui::VKEY_3, ui::EF_NONE, 3);
  EXPECT_FALSE(event_capturer_.last_key_event());

  // Press the "4" key from the unknown keyboard which is captured by
  // AccessibilityEventRewriter.
  generator_->PressKey(ui::VKEY_4, ui::EF_NONE, 4);
  generator_->ReleaseKey(ui::VKEY_4, ui::EF_NONE, 2);
  EXPECT_FALSE(event_capturer_.last_key_event());

  // Now, exclude some device types.
  rewriter->SetKeyboardInputDeviceTypes(
      {ui::INPUT_DEVICE_USB, ui::INPUT_DEVICE_BLUETOOTH});

  // Press the "1" key from the internal keyboard which is not captured by
  // AccessibilityEventRewriter.
  generator_->PressKey(ui::VKEY_1, ui::EF_NONE, 1);
  generator_->ReleaseKey(ui::VKEY_1, ui::EF_NONE, 1);
  EXPECT_TRUE(event_capturer_.last_key_event());
  event_capturer_.Reset();

  // Press the "2" key from the usb keyboard which is captured by
  // AccessibilityEventRewriter.
  generator_->PressKey(ui::VKEY_2, ui::EF_NONE, 2);
  generator_->ReleaseKey(ui::VKEY_2, ui::EF_NONE, 2);
  EXPECT_FALSE(event_capturer_.last_key_event());

  // Press the "3" key from the bluetooth keyboard which is captured by
  // AccessibilityEventRewriter.
  generator_->PressKey(ui::VKEY_3, ui::EF_NONE, 3);
  generator_->ReleaseKey(ui::VKEY_3, ui::EF_NONE, 3);
  EXPECT_FALSE(event_capturer_.last_key_event());

  // Press the "4" key from the unknown keyboard which is not captured by
  // AccessibilityEventRewriter.
  generator_->PressKey(ui::VKEY_4, ui::EF_NONE, 4);
  generator_->ReleaseKey(ui::VKEY_4, ui::EF_NONE, 2);
  EXPECT_TRUE(event_capturer_.last_key_event());
}

}  // namespace
}  // namespace ash
