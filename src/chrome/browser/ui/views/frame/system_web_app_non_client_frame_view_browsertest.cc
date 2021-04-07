// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/views/frame/browser_non_client_frame_view.h"

#include "chrome/browser/ui/views/web_apps/web_app_frame_toolbar_view.h"
#include "chrome/browser/ui/web_applications/test/web_app_browsertest_util.h"
#include "chrome/browser/web_applications/system_web_app_manager.h"
#include "chrome/browser/web_applications/system_web_app_manager_browsertest.h"
#include "chrome/test/base/in_process_browser_test.h"
#include "chrome/test/base/ui_test_utils.h"
#include "content/public/test/browser_test.h"

using SystemWebAppNonClientFrameViewBrowserTest =
    web_app::SystemWebAppManagerBrowserTest;

// System Web Apps don't get the web app menu button.
IN_PROC_BROWSER_TEST_P(SystemWebAppNonClientFrameViewBrowserTest,
                       HideWebAppMenuButton) {
  WaitForTestSystemAppInstall();
  Browser* app_browser;
  LaunchApp(web_app::SystemAppType::SETTINGS, &app_browser);
  EXPECT_EQ(nullptr, BrowserView::GetBrowserViewForBrowser(app_browser)
                         ->frame()
                         ->GetFrameView()
                         ->web_app_frame_toolbar_for_testing()
                         ->GetAppMenuButton());
}

// Regression test for https://crbug.com/1090169.
IN_PROC_BROWSER_TEST_P(SystemWebAppNonClientFrameViewBrowserTest,
                       HideNativeFileSystemAccessPageAction) {
  WaitForTestSystemAppInstall();
  Browser* app_browser;
  LaunchApp(web_app::SystemAppType::SETTINGS, &app_browser);
  WebAppFrameToolbarView* toolbar =
      BrowserView::GetBrowserViewForBrowser(app_browser)
          ->frame()
          ->GetFrameView()
          ->web_app_frame_toolbar_for_testing();
  EXPECT_FALSE(toolbar->GetPageActionIconView(
      PageActionIconType::kNativeFileSystemAccess));
}

INSTANTIATE_SYSTEM_WEB_APP_MANAGER_TEST_SUITE_MANIFEST_INSTALL_P(
    SystemWebAppNonClientFrameViewBrowserTest);
