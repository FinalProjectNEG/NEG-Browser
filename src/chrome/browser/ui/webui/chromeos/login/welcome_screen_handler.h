// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_WEBUI_CHROMEOS_LOGIN_WELCOME_SCREEN_HANDLER_H_
#define CHROME_BROWSER_UI_WEBUI_CHROMEOS_LOGIN_WELCOME_SCREEN_HANDLER_H_

#include <memory>
#include <string>

#include "base/macros.h"
#include "chrome/browser/chromeos/accessibility/accessibility_manager.h"
#include "chrome/browser/ui/webui/chromeos/login/base_screen_handler.h"

namespace base {
class ListValue;
}

namespace chromeos {

class CoreOobeView;
class WelcomeScreen;

// Interface for WelcomeScreenHandler.
class WelcomeView {
 public:
  constexpr static StaticOobeScreenId kScreenId{"connect"};

  virtual ~WelcomeView() {}

  // Shows the contents of the screen.
  virtual void Show() = 0;

  // Hides the contents of the screen.
  virtual void Hide() = 0;

  // Binds |screen| to the view.
  virtual void Bind(WelcomeScreen* screen) = 0;

  // Unbinds model from the view.
  virtual void Unbind() = 0;

  // Reloads localized contents.
  virtual void ReloadLocalizedContent() = 0;

  // Change the current input method.
  virtual void SetInputMethodId(const std::string& input_method_id) = 0;

  // Shows dialog to confirm starting Demo mode.
  virtual void ShowDemoModeConfirmationDialog() = 0;
};

// WebUI implementation of WelcomeScreenView. It is used to interact with
// the welcome screen (part of the page) of the OOBE.
class WelcomeScreenHandler : public WelcomeView, public BaseScreenHandler {
 public:
  using TView = WelcomeView;

  WelcomeScreenHandler(JSCallsContainer* js_calls_container,
                       CoreOobeView* core_oobe_view);
  ~WelcomeScreenHandler() override;

  // WelcomeView:
  void Show() override;
  void Hide() override;
  void Bind(WelcomeScreen* screen) override;
  void Unbind() override;
  void ReloadLocalizedContent() override;
  void SetInputMethodId(const std::string& input_method_id) override;
  void ShowDemoModeConfirmationDialog() override;

  // BaseScreenHandler:
  void DeclareLocalizedValues(
      ::login::LocalizedValuesBuilder* builder) override;
  void DeclareJSCallbacks() override;
  void GetAdditionalParameters(base::DictionaryValue* dict) override;
  void Initialize() override;

 private:
  // JS callbacks.
  void HandleSetLocaleId(const std::string& locale_id);
  void HandleSetInputMethodId(const std::string& input_method_id);
  void HandleSetTimezoneId(const std::string& timezone_id);
  void HandleEnableLargeCursor(bool enabled);
  void HandleEnableHighContrast(bool enabled);
  void HandleEnableVirtualKeyboard(bool enabled);
  void HandleEnableScreenMagnifier(bool enabled);
  void HandleEnableSpokenFeedback(bool /* enabled */);
  void HandleEnableSelectToSpeak(bool /* enabled */);
  void HandleEnableDockedMagnifier(bool /* enabled */);

  // Notification of a change in the accessibility settings.
  void OnAccessibilityStatusChanged(
      const AccessibilityStatusEventDetails& details);

  // Updates a11y menu state based on the current a11y features state(on/off).
  void UpdateA11yState();

  // Returns available timezones. Caller gets the ownership.
  static std::unique_ptr<base::ListValue> GetTimezoneList();

  CoreOobeView* core_oobe_view_ = nullptr;
  WelcomeScreen* screen_ = nullptr;

  // Keeps whether screen should be shown right after initialization.
  bool show_on_init_ = false;

  std::unique_ptr<AccessibilityStatusSubscription> accessibility_subscription_;

  DISALLOW_COPY_AND_ASSIGN(WelcomeScreenHandler);
};

}  // namespace chromeos

#endif  // CHROME_BROWSER_UI_WEBUI_CHROMEOS_LOGIN_WELCOME_SCREEN_HANDLER_H_
