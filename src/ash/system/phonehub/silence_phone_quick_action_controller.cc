// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ash/system/phonehub/silence_phone_quick_action_controller.h"

#include "ash/resources/vector_icons/vector_icons.h"
#include "ash/strings/grit/ash_strings.h"
#include "ash/system/phonehub/quick_action_item.h"
#include "base/timer/timer.h"
#include "ui/base/l10n/l10n_util.h"

namespace ash {

namespace {

// Time to wait until we check the state of the phone to prevent showing wrong
// state
constexpr base::TimeDelta kWaitForRequestTimeout =
    base::TimeDelta::FromSeconds(10);

}  // namespace

SilencePhoneQuickActionController::SilencePhoneQuickActionController(
    chromeos::phonehub::DoNotDisturbController* dnd_controller)
    : dnd_controller_(dnd_controller) {
  DCHECK(dnd_controller_);
  dnd_controller_->AddObserver(this);
}

SilencePhoneQuickActionController::~SilencePhoneQuickActionController() {
  dnd_controller_->RemoveObserver(this);
}

QuickActionItem* SilencePhoneQuickActionController::CreateItem() {
  DCHECK(!item_);
  item_ = new QuickActionItem(this, IDS_ASH_PHONE_HUB_SILENCE_PHONE_TITLE,
                              kSystemMenuPhoneIcon);
  OnDndStateChanged();
  return item_;
}

void SilencePhoneQuickActionController::OnButtonPressed(bool is_now_enabled) {
  requested_state_ = is_now_enabled ? ActionState::kOff : ActionState::kOn;
  SetItemState(requested_state_.value());

  check_requested_state_timer_ = std::make_unique<base::OneShotTimer>();
  check_requested_state_timer_->Start(
      FROM_HERE, kWaitForRequestTimeout,
      base::BindOnce(&SilencePhoneQuickActionController::CheckRequestedState,
                     base::Unretained(this)));

  dnd_controller_->RequestNewDoNotDisturbState(!is_now_enabled);
}

void SilencePhoneQuickActionController::OnDndStateChanged() {
  state_ =
      dnd_controller_->IsDndEnabled() ? ActionState::kOn : ActionState::kOff;
  SetItemState(state_);

  // If |requested_state_| correctly resembles the current state, reset it and
  // the timer.
  if (state_ == requested_state_) {
    check_requested_state_timer_.reset();
    requested_state_.reset();
  }
}

void SilencePhoneQuickActionController::SetItemState(ActionState state) {
  bool icon_enabled;
  int state_text_id;
  int sub_label_text;
  switch (state) {
    case ActionState::kOff:
      icon_enabled = false;
      state_text_id = IDS_ASH_PHONE_HUB_QUICK_ACTIONS_DISABLED_STATE_TOOLTIP;
      sub_label_text = IDS_ASH_PHONE_HUB_QUICK_ACTIONS_OFF_STATE;
      break;
    case ActionState::kOn:
      icon_enabled = true;
      state_text_id = IDS_ASH_PHONE_HUB_QUICK_ACTIONS_ENABLED_STATE_TOOLTIP;
      sub_label_text = IDS_ASH_PHONE_HUB_QUICK_ACTIONS_ON_STATE;
      break;
  }

  item_->SetToggled(icon_enabled);
  item_->SetSubLabel(l10n_util::GetStringUTF16(sub_label_text));
  base::string16 tooltip_state =
      l10n_util::GetStringFUTF16(state_text_id, item_->GetItemLabel());
  item_->SetIconTooltip(
      l10n_util::GetStringFUTF16(IDS_ASH_PHONE_HUB_QUICK_ACTIONS_TOGGLE_TOOLTIP,
                                 item_->GetItemLabel(), tooltip_state));
}

void SilencePhoneQuickActionController::CheckRequestedState() {
  // If the current state is different from the requested state, it means that
  // we fail to change the state, so switch back to the original one.
  if (state_ != requested_state_)
    SetItemState(state_);

  check_requested_state_timer_.reset();
  requested_state_.reset();
}

}  // namespace ash
