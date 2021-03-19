// Copyright (c) 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/chromeos/input_method/assistive_window_controller.h"

#include <string>
#include <vector>

#include "ash/public/cpp/ash_pref_names.h"
#include "ash/public/cpp/shell_window_ids.h"
#include "ash/shell.h"
#include "ash/wm/window_util.h"
#include "chrome/browser/chromeos/input_method/assistive_window_controller_delegate.h"
#include "chrome/browser/chromeos/input_method/assistive_window_properties.h"
#include "chrome/browser/chromeos/input_method/ui/suggestion_details.h"
#include "chrome/browser/profiles/profile_manager.h"
#include "chrome/grit/generated_resources.h"
#include "components/prefs/pref_service.h"
#include "ui/base/ime/chromeos/ime_bridge.h"
#include "ui/base/l10n/l10n_util.h"
#include "ui/views/widget/widget.h"

namespace chromeos {
namespace input_method {

namespace {
gfx::NativeView GetParentView() {
  gfx::NativeView parent = nullptr;

  aura::Window* active_window = ash::window_util::GetActiveWindow();
  // Use VirtualKeyboardContainer so that it works even with a system modal
  // dialog.
  parent = ash::Shell::GetContainer(
      active_window ? active_window->GetRootWindow()
                    : ash::Shell::GetRootWindowForNewWindows(),
      ash::kShellWindowId_VirtualKeyboardContainer);
  return parent;
}

constexpr base::TimeDelta kTtsShowDelay =
    base::TimeDelta::FromMilliseconds(100);

}  // namespace

TtsHandler::TtsHandler(Profile* profile) : profile_(profile) {}
TtsHandler::~TtsHandler() = default;

void TtsHandler::Announce(const std::string& text,
                          const base::TimeDelta delay) {
  const bool chrome_vox_enabled = profile_->GetPrefs()->GetBoolean(
      ash::prefs::kAccessibilitySpokenFeedbackEnabled);
  if (!chrome_vox_enabled)
    return;

  delay_timer_ = std::make_unique<base::OneShotTimer>();
  delay_timer_->Start(
      FROM_HERE, delay,
      base::BindOnce(&TtsHandler::Speak, base::Unretained(this), text));
}

void TtsHandler::OnTtsEvent(content::TtsUtterance* utterance,
                            content::TtsEventType event_type,
                            int char_index,
                            int length,
                            const std::string& error_message) {}

void TtsHandler::Speak(const std::string& text) {
  std::unique_ptr<content::TtsUtterance> utterance =
      content::TtsUtterance::Create(profile_);
  utterance->SetText(text);
  utterance->SetEventDelegate(this);

  auto* tts_controller = content::TtsController::GetInstance();
  tts_controller->Stop();
  tts_controller->SpeakOrEnqueue(std::move(utterance));
}

AssistiveWindowController::AssistiveWindowController(
    AssistiveWindowControllerDelegate* delegate,
    Profile* profile,
    std::unique_ptr<TtsHandler> tts_handler)
    : delegate_(delegate),
      tts_handler_(tts_handler ? std::move(tts_handler)
                               : std::make_unique<TtsHandler>(profile)) {}

AssistiveWindowController::~AssistiveWindowController() {
  if (suggestion_window_view_ && suggestion_window_view_->GetWidget())
    suggestion_window_view_->GetWidget()->RemoveObserver(this);
  if (undo_window_ && undo_window_->GetWidget())
    undo_window_->GetWidget()->RemoveObserver(this);
  CHECK(!IsInObserverList());
}

void AssistiveWindowController::InitSuggestionWindow() {
  if (suggestion_window_view_)
    return;
  // suggestion_window_view_ is deleted by DialogDelegateView::DeleteDelegate.
  suggestion_window_view_ =
      ui::ime::SuggestionWindowView::Create(GetParentView(), this);
  views::Widget* widget = suggestion_window_view_->GetWidget();
  widget->AddObserver(this);
  widget->Show();
}

void AssistiveWindowController::InitUndoWindow() {
  if (undo_window_)
    return;
  // undo_window is deleted by DialogDelegateView::DeleteDelegate.
  undo_window_ = new ui::ime::UndoWindow(GetParentView(), this);
  views::Widget* widget = undo_window_->InitWidget();
  widget->AddObserver(this);
  widget->Show();
}

void AssistiveWindowController::OnWidgetClosing(views::Widget* widget) {
  if (suggestion_window_view_ &&
      widget == suggestion_window_view_->GetWidget()) {
    widget->RemoveObserver(this);
    suggestion_window_view_ = nullptr;
  }
  if (undo_window_ && widget == undo_window_->GetWidget()) {
    widget->RemoveObserver(this);
    undo_window_ = nullptr;
  }
}

// TODO(crbug/1119570): Update AcceptSuggestion signature (either use
// announce_string, or no string)
void AssistiveWindowController::AcceptSuggestion(
    const base::string16& suggestion) {
  if (window_.type == ui::ime::AssistiveWindowType::kEmojiSuggestion) {
    tts_handler_->Announce(
        l10n_util::GetStringUTF8(IDS_SUGGESTION_EMOJI_SUGGESTED));
  } else {
    tts_handler_->Announce(l10n_util::GetStringUTF8(IDS_SUGGESTION_INSERTED));
  }
  HideSuggestion();
}

void AssistiveWindowController::HideSuggestion() {
  suggestion_text_ = base::EmptyString16();
  confirmed_length_ = 0;
  if (suggestion_window_view_)
    suggestion_window_view_->GetWidget()->Close();
}

void AssistiveWindowController::SetBounds(const Bounds& bounds) {
  bounds_ = bounds;
  // Sets suggestion_window_view_'s bounds here for most up-to-date cursor
  // position. This is different from UndoWindow because UndoWindow gets cursors
  // position before showing.
  // TODO(crbug/1112982): Investigate getting bounds to suggester before sending
  // show suggestion request.
  if (suggestion_window_view_ && confirmed_length_ == 0)
    suggestion_window_view_->SetAnchorRect(bounds.caret);
}

void AssistiveWindowController::FocusStateChanged() {
  if (suggestion_window_view_)
    HideSuggestion();
  if (undo_window_)
    undo_window_->Hide();
}

void AssistiveWindowController::ShowSuggestion(
    const ui::ime::SuggestionDetails& details) {
  if (!suggestion_window_view_)
    InitSuggestionWindow();
  suggestion_text_ = details.text;
  confirmed_length_ = details.confirmed_length;
  suggestion_window_view_->Show(details);
}

// TODO(crbug/1102219): Method unused. Remove all definitions and references.
void AssistiveWindowController::ShowMultipleSuggestions(
    const std::vector<base::string16>& suggestions) {
}

void AssistiveWindowController::SetButtonHighlighted(
    const ui::ime::AssistiveWindowButton& button,
    bool highlighted) {
  switch (button.window_type) {
    case ui::ime::AssistiveWindowType::kEmojiSuggestion:
    case ui::ime::AssistiveWindowType::kPersonalInfoSuggestion:
      if (!suggestion_window_view_)
        return;

      suggestion_window_view_->SetButtonHighlighted(button, highlighted);
      if (highlighted)
        tts_handler_->Announce(button.announce_string);
      break;
    case ui::ime::AssistiveWindowType::kUndoWindow:
      if (!undo_window_)
        return;

      undo_window_->SetButtonHighlighted(button, highlighted);
      tts_handler_->Announce(button.announce_string);
      break;
    case ui::ime::AssistiveWindowType::kNone:
      break;
  }
}

base::string16 AssistiveWindowController::GetSuggestionText() const {
  return suggestion_text_;
}

size_t AssistiveWindowController::GetConfirmedLength() const {
  return confirmed_length_;
}

void AssistiveWindowController::SetAssistiveWindowProperties(
    const AssistiveWindowProperties& window) {
  window_ = window;
  switch (window.type) {
    case ui::ime::AssistiveWindowType::kUndoWindow:
      if (!undo_window_)
        InitUndoWindow();
      if (window.visible) {
        undo_window_->SetAnchorRect(bounds_.autocorrect.IsEmpty()
                                        ? bounds_.caret
                                        : bounds_.autocorrect);
        undo_window_->Show();
      } else {
        undo_window_->Hide();
      }
      break;
    case ui::ime::AssistiveWindowType::kEmojiSuggestion:
    case ui::ime::AssistiveWindowType::kPersonalInfoSuggestion:
      if (!suggestion_window_view_)
        InitSuggestionWindow();
      if (window_.visible) {
        suggestion_window_view_->ShowMultipleCandidates(window);
      } else {
        HideSuggestion();
      }
      break;
    case ui::ime::AssistiveWindowType::kNone:
      break;
  }
  tts_handler_->Announce(window.announce_string, kTtsShowDelay);
}

void AssistiveWindowController::AssistiveWindowButtonClicked(
    const ui::ime::AssistiveWindowButton& button) const {
    delegate_->AssistiveWindowButtonClicked(button);
}

ui::ime::SuggestionWindowView*
AssistiveWindowController::GetSuggestionWindowViewForTesting() {
  return suggestion_window_view_;
}

ui::ime::UndoWindow* AssistiveWindowController::GetUndoWindowForTesting()
    const {
  return undo_window_;
}

}  // namespace input_method
}  // namespace chromeos
