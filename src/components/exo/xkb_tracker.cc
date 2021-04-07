// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/exo/xkb_tracker.h"

#if BUILDFLAG(USE_XKBCOMMON)
#include "components/exo/keyboard_modifiers.h"
#include "ui/events/ozone/layout/xkb/xkb_keyboard_layout_engine.h"
#endif

namespace exo {

#if BUILDFLAG(USE_XKBCOMMON)
XkbTracker::XkbTracker() {
  UpdateKeyboardLayoutInternal(nullptr);
  UpdateKeyboardModifiersInternal();
}
#else
XkbTracker::XkbTracker() = default;
#endif

XkbTracker::~XkbTracker() = default;

#if BUILDFLAG(USE_XKBCOMMON)

void XkbTracker::UpdateKeyboardLayout(const std::string& name) {
  std::string layout_id, layout_variant;
  ui::XkbKeyboardLayoutEngine::ParseLayoutName(name, &layout_id,
                                               &layout_variant);
  xkb_rule_names names = {.rules = nullptr,
                          .model = "pc101",
                          .layout = layout_id.c_str(),
                          .variant = layout_variant.c_str(),
                          .options = ""};
  UpdateKeyboardLayoutInternal(&names);
  UpdateKeyboardModifiersInternal();
}

void XkbTracker::UpdateKeyboardModifiers(int modifier_flags) {
  // CrOS treats numlock as always on, but its event flags actually have that
  // key disabled, (i.e. chromeos apps specially handle numpad key events as
  // though numlock is on). In order to get the same result from the linux apps,
  // we need to ensure they always treat numlock as on.
  modifier_flags_ = modifier_flags | ui::EF_NUM_LOCK_ON;
  UpdateKeyboardModifiersInternal();
}

uint32_t XkbTracker::GetKeysym(uint32_t xkb_keycode) const {
  return xkb_state_key_get_one_sym(xkb_state_.get(), xkb_keycode);
}

std::unique_ptr<char, base::FreeDeleter> XkbTracker::GetKeymap() const {
  return std::unique_ptr<char, base::FreeDeleter>(
      xkb_keymap_get_as_string(xkb_keymap_.get(), XKB_KEYMAP_FORMAT_TEXT_V1));
}

KeyboardModifiers XkbTracker::GetModifiers() const {
  return {
      xkb_state_serialize_mods(xkb_state_.get(), XKB_STATE_MODS_DEPRESSED),
      xkb_state_serialize_mods(xkb_state_.get(), XKB_STATE_MODS_LOCKED),
      xkb_state_serialize_mods(xkb_state_.get(), XKB_STATE_MODS_LATCHED),
      xkb_state_serialize_layout(xkb_state_.get(), XKB_STATE_LAYOUT_EFFECTIVE),
  };
}

void XkbTracker::UpdateKeyboardLayoutInternal(const xkb_rule_names* names) {
  xkb_keymap_.reset(xkb_keymap_new_from_names(xkb_context_.get(), names,
                                              XKB_KEYMAP_COMPILE_NO_FLAGS));
  xkb_state_.reset(xkb_state_new(xkb_keymap_.get()));
}

void XkbTracker::UpdateKeyboardModifiersInternal() {
  constexpr struct {
    ui::EventFlags flag;
    const char* xkb_name;
  } modifiers[] = {
      {ui::EF_SHIFT_DOWN, XKB_MOD_NAME_SHIFT},
      {ui::EF_CONTROL_DOWN, XKB_MOD_NAME_CTRL},
      {ui::EF_ALT_DOWN, XKB_MOD_NAME_ALT},
      {ui::EF_COMMAND_DOWN, XKB_MOD_NAME_LOGO},
      {ui::EF_ALTGR_DOWN, "Mod5"},
      {ui::EF_MOD3_DOWN, "Mod3"},
      {ui::EF_NUM_LOCK_ON, XKB_MOD_NAME_NUM},
      {ui::EF_CAPS_LOCK_ON, XKB_MOD_NAME_CAPS},
  };
  uint32_t xkb_modifiers = 0;
  for (const auto& modifier : modifiers) {
    if (modifier_flags_ & modifier.flag) {
      xkb_modifiers |=
          1 << xkb_keymap_mod_get_index(xkb_keymap_.get(), modifier.xkb_name);
    }
  }
  xkb_state_update_mask(xkb_state_.get(), xkb_modifiers, 0, 0, 0, 0, 0);
}

#endif  // BUILDFLAG(USE_XKBCOMMON)

}  // namespace exo
