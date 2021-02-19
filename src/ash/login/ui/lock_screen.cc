// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ash/login/ui/lock_screen.h"

#include <algorithm>
#include <memory>
#include <utility>

#include "ash/login/ui/lock_contents_view.h"
#include "ash/login/ui/lock_debug_view.h"
#include "ash/login/ui/login_data_dispatcher.h"
#include "ash/login/ui/login_detachable_base_model.h"
#include "ash/public/cpp/lock_screen_widget_factory.h"
#include "ash/public/cpp/shell_window_ids.h"
#include "ash/shelf/login_shelf_view.h"
#include "ash/shelf/shelf.h"
#include "ash/shelf/shelf_widget.h"
#include "ash/shell.h"
#include "ash/wallpaper/wallpaper_controller_impl.h"
#include "base/bind.h"
#include "base/callback.h"
#include "base/command_line.h"
#include "chromeos/constants/chromeos_switches.h"
#include "ui/display/display.h"
#include "ui/display/screen.h"
#include "ui/views/widget/widget.h"
#include "ui/wm/core/capture_controller.h"

namespace ash {
namespace {

// Global lock screen instance. There can only ever be on lock screen at a
// time.
LockScreen* instance_ = nullptr;

}  // namespace

LockScreen::TestApi::TestApi(LockScreen* lock_screen)
    : lock_screen_(lock_screen) {}

LockScreen::TestApi::~TestApi() = default;

LockContentsView* LockScreen::TestApi::contents_view() const {
  return lock_screen_->contents_view_;
}

void LockScreen::TestApi::AddOnShownCallback(base::OnceClosure on_shown) {
  if (lock_screen_->is_shown_) {
    std::move(on_shown).Run();
    return;
  }
  lock_screen_->on_shown_callbacks_.push_back(std::move(on_shown));
}

LockScreen::LockScreen(ScreenType type) : type_(type) {
  tray_action_observer_.Add(Shell::Get()->tray_action());
  saved_clipboard_ = ui::Clipboard::TakeForCurrentThread();
}

LockScreen::~LockScreen() {
  widget_.reset();

  ui::Clipboard::DestroyClipboardForCurrentThread();
  if (saved_clipboard_)
    ui::Clipboard::SetClipboardForCurrentThread(std::move(saved_clipboard_));
}

std::unique_ptr<views::View> LockScreen::MakeContentsView() {
  auto initial_note_action_state =
      Shell::Get()->tray_action()->GetLockScreenNoteState();
  if (base::CommandLine::ForCurrentProcess()->HasSwitch(
          chromeos::switches::kShowLoginDevOverlay)) {
    auto debug_view =
        std::make_unique<LockDebugView>(initial_note_action_state, type_);
    contents_view_ = debug_view->lock();
    return debug_view;
  }

  auto detachable_base_model =
      LoginDetachableBaseModel::Create(Shell::Get()->detachable_base_handler());
  auto view = std::make_unique<LockContentsView>(
      initial_note_action_state, type_,
      Shell::Get()->login_screen_controller()->data_dispatcher(),
      std::move(detachable_base_model));
  contents_view_ = view.get();
  return view;
}

// static
LockScreen* LockScreen::Get() {
  CHECK(instance_);
  return instance_;
}

// static
void LockScreen::Show(ScreenType type) {
  CHECK(!instance_);
  // Capture should be released when locked.
  ::wm::CaptureController::Get()->SetCapture(nullptr);

  instance_ = new LockScreen(type);

  aura::Window* parent = nullptr;
  if (Shell::HasInstance()) {
    parent = Shell::GetContainer(Shell::GetPrimaryRootWindow(),
                                 kShellWindowId_LockScreenContainer);
  }
  instance_->widget_ =
      CreateLockScreenWidget(parent, instance_->MakeContentsView());
  instance_->widget_->SetBounds(
      display::Screen::GetScreen()->GetPrimaryDisplay().bounds());

  // Postpone showing the screen after the animation of the first wallpaper
  // completes, to make the transition smooth. The callback will be dispatched
  // immediately if the animation is already complete (e.g. kLock).
  Shell::Get()->wallpaper_controller()->AddFirstWallpaperAnimationEndCallback(
      base::BindOnce(&LockScreen::ShowWidgetUponWallpaperReady),
      instance_->widget_->GetNativeView());
}

// static
bool LockScreen::HasInstance() {
  return !!instance_;
}

void LockScreen::Destroy() {
  LoginScreenController::AuthenticationStage authentication_stage =
      Shell::Get()->login_screen_controller()->authentication_stage();
  base::debug::Alias(&authentication_stage);
  if (Shell::Get()->login_screen_controller()->authentication_stage() !=
      authentication_stage) {
    LOG(FATAL) << "Unexpected authentication stage "
               << static_cast<int>(authentication_stage);
  }
  CHECK_EQ(instance_, this);

  Shell::Get()->login_screen_controller()->data_dispatcher()->RemoveObserver(
      Shelf::ForWindow(Shell::GetPrimaryRootWindow())
          ->shelf_widget()
          ->login_shelf_view());

  delete instance_;
  instance_ = nullptr;
}

void LockScreen::FocusNextUser() {
  contents_view_->FocusNextUser();
}

void LockScreen::FocusPreviousUser() {
  contents_view_->FocusPreviousUser();
}

void LockScreen::ShowParentAccessDialog() {
  contents_view_->ShowParentAccessDialog();
}

void LockScreen::OnLockScreenNoteStateChanged(mojom::TrayActionState state) {
  Shell::Get()
      ->login_screen_controller()
      ->data_dispatcher()
      ->SetLockScreenNoteState(state);
}

void LockScreen::OnSessionStateChanged(session_manager::SessionState state) {
  if (type_ == ScreenType::kLogin &&
      state == session_manager::SessionState::ACTIVE) {
    Destroy();
  }
}

void LockScreen::OnLockStateChanged(bool locked) {
  if (type_ != ScreenType::kLock)
    return;

  if (!locked)
    Destroy();
}

void LockScreen::OnChromeTerminating() {
  Destroy();
}

// static
void LockScreen::ShowWidgetUponWallpaperReady() {
  // |instance_| may already be destroyed in tests.
  if (!instance_ || instance_->is_shown_)
    return;
  instance_->is_shown_ = true;
  instance_->widget_->Show();

  std::vector<base::OnceClosure> on_shown_callbacks;
  swap(instance_->on_shown_callbacks_, on_shown_callbacks);
  for (auto& callback : on_shown_callbacks)
    std::move(callback).Run();

  Shell::Get()->login_screen_controller()->NotifyLoginScreenShown();
}

}  // namespace ash
