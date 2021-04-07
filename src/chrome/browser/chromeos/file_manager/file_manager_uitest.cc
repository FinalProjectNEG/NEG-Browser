// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/path_service.h"
#include "base/strings/stringprintf.h"
#include "chrome/browser/ui/browser.h"
#include "chrome/test/base/in_process_browser_test.h"
#include "chrome/test/base/ui_test_utils.h"
#include "content/public/browser/render_view_host.h"
#include "content/public/common/content_switches.h"
#include "content/public/test/browser_test.h"
#include "content/public/test/browser_test_utils.h"
#include "net/base/filename_util.h"
#include "third_party/blink/public/common/web_preferences/web_preferences.h"

namespace file_manager {

// Test fixture class for FileManager UI.
class FileManagerUITest : public InProcessBrowserTest {
 public:
  void SetUpCommandLine(base::CommandLine* command_line) override {
    // --disable-web-security required to load resources from files.
    command_line->AppendSwitch(switches::kDisableWebSecurity);
  }

  void RunTest(std::string test_scope) {
    base::FilePath root_path;
    ASSERT_TRUE(base::PathService::Get(base::DIR_MODULE, &root_path));

    // Load test.html.
    const GURL url = net::FilePathToFileURL(root_path.Append(
        FILE_PATH_LITERAL("gen/ui/file_manager/file_manager/test.html")));
    content::WebContents* const web_contents =
        browser()->tab_strip_model()->GetActiveWebContents();

    // Set prefs required for cut/paste.
    auto web_prefs = web_contents->GetOrCreateWebPreferences();
    web_prefs.dom_paste_enabled = true;
    web_prefs.javascript_can_access_clipboard = true;
    web_contents->SetWebPreferences(web_prefs);

    ASSERT_TRUE(web_contents);
    ui_test_utils::NavigateToURL(browser(), url);

    // Load and run specified test file.
    content::DOMMessageQueue message_queue;
    ExecuteScriptAsync(web_contents,
                       base::StringPrintf("runTests(%s)", test_scope.c_str()));

    // Wait for JS to call domAutomationController.send("SUCCESS").
    std::string message;
    do {
      EXPECT_TRUE(message_queue.WaitForMessage(&message));
    } while (message == "\"PENDING\"");

    EXPECT_EQ(message, "\"SUCCESS\"");
  }
};

IN_PROC_BROWSER_TEST_F(FileManagerUITest, CheckSelect) {
  RunTest("checkselect");
}

IN_PROC_BROWSER_TEST_F(FileManagerUITest, CrostiniMount) {
  RunTest("crostiniMount");
}

IN_PROC_BROWSER_TEST_F(FileManagerUITest, CrostiniShare) {
  RunTest("crostiniShare");
}

IN_PROC_BROWSER_TEST_F(FileManagerUITest, CrostiniShareManage) {
  RunTest("crostiniShareManage");
}

IN_PROC_BROWSER_TEST_F(FileManagerUITest, CrostiniShareVolumes) {
  RunTest("crostiniShareVolumes");
}

IN_PROC_BROWSER_TEST_F(FileManagerUITest, CrostiniTasks) {
  RunTest("crostiniTasks");
}

IN_PROC_BROWSER_TEST_F(FileManagerUITest, Menu) {
  RunTest("menu");
}

IN_PROC_BROWSER_TEST_F(FileManagerUITest, PluginVm) {
  RunTest("pluginVm");
}

IN_PROC_BROWSER_TEST_F(FileManagerUITest, PluginVmShare) {
  RunTest("pluginVmShare");
}

IN_PROC_BROWSER_TEST_F(FileManagerUITest, PluginVmShareManage) {
  RunTest("pluginVmShareManage");
}

IN_PROC_BROWSER_TEST_F(FileManagerUITest, PluginVmShareVolumes) {
  RunTest("pluginVmShareVolumes");
}

}  // namespace file_manager
