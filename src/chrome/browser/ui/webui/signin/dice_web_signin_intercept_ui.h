// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_WEBUI_SIGNIN_DICE_WEB_SIGNIN_INTERCEPT_UI_H_
#define CHROME_BROWSER_UI_WEBUI_SIGNIN_DICE_WEB_SIGNIN_INTERCEPT_UI_H_

#include "content/public/browser/web_ui_controller.h"

#include "base/callback.h"
#include "chrome/browser/signin/dice_web_signin_interceptor.h"

namespace content {
class WebUI;
}

class DiceWebSigninInterceptUI : public content::WebUIController {
 public:
  explicit DiceWebSigninInterceptUI(content::WebUI* web_ui);
  ~DiceWebSigninInterceptUI() override;

  DiceWebSigninInterceptUI(const DiceWebSigninInterceptUI&) = delete;
  DiceWebSigninInterceptUI& operator=(const DiceWebSigninInterceptUI&) = delete;

  // Initializes the DiceWebSigninInterceptUI.
  void Initialize(const DiceWebSigninInterceptor::Delegate::BubbleParameters&
                      bubble_parameters,
                  base::OnceCallback<void(bool)> callback);

 private:
  WEB_UI_CONTROLLER_TYPE_DECL();
};

#endif  // CHROME_BROWSER_UI_WEBUI_SIGNIN_DICE_WEB_SIGNIN_INTERCEPT_UI_H_
