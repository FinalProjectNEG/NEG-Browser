// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/scoped_feature_list.h"
#include "base/unguessable_token.h"
#include "chrome/browser/extensions/extension_browsertest.h"
#include "chrome/browser/ui/browser.h"
#include "chrome/browser/ui/tabs/tab_strip_model.h"
#include "chrome/browser/ui/web_applications/web_app_controller_browsertest.h"
#include "chrome/browser/web_applications/components/web_app_tab_helper_base.h"
#include "chrome/browser/web_applications/test/web_app_test.h"
#include "chrome/test/base/ui_test_utils.h"
#include "content/public/browser/web_contents.h"
#include "content/public/test/browser_test.h"
#include "content/public/test/browser_test_utils.h"
#include "net/test/embedded_test_server/embedded_test_server.h"
#include "services/media_session/public/cpp/features.h"
#include "ui/base/page_transition_types.h"
#include "url/gurl.h"
#include "url/third_party/mozilla/url_parse.h"
#include "url/url_canon.h"

namespace web_app {

namespace {

const char kAudioFocusTestPageURL[] =
    "/extensions/audio_focus_web_app/main.html";

}  // namespace

// WebAppAudioFocusBrowserTest test that PWAs have separate audio
// focus from the rest of the browser.
class WebAppAudioFocusBrowserTest : public WebAppControllerBrowserTest {
 public:
  WebAppAudioFocusBrowserTest() = default;
  ~WebAppAudioFocusBrowserTest() override = default;

  void SetUp() override {
    scoped_feature_list_.InitWithFeatures(
        {media_session::features::kMediaSessionService,
         media_session::features::kAudioFocusEnforcement,
         media_session::features::kAudioFocusSessionGrouping},
        {});

    WebAppControllerBrowserTest::SetUp();
  }

  bool IsPaused(content::WebContents* web_contents) {
    bool result = false;
    EXPECT_TRUE(content::ExecuteScriptAndExtractBool(web_contents, "isPaused()",
                                                     &result));
    return result;
  }

  bool WaitForPause(content::WebContents* web_contents) {
    bool result = false;
    EXPECT_TRUE(content::ExecuteScriptAndExtractBool(
        web_contents, "waitForPause()", &result));
    return result;
  }

  bool StartPlaying(content::WebContents* web_contents) {
    bool result = false;
    return content::ExecuteScriptAndExtractBool(web_contents, "startPlaying()",
                                                &result) &&
           result;
  }

  content::WebContents* AddTestPageTabAtIndex(int index) {
    AddTabAtIndex(index, embedded_test_server()->GetURL(kAudioFocusTestPageURL),
                  ui::PAGE_TRANSITION_TYPED);
    content::WebContents* tab =
        browser()->tab_strip_model()->GetActiveWebContents();
    EXPECT_TRUE(content::WaitForLoadStop(tab));
    return tab;
  }

  const base::UnguessableToken& GetAudioFocusGroupId(
      content::WebContents* web_contents) {
    WebAppTabHelperBase* helper =
        WebAppTabHelperBase::FromWebContents(web_contents);
    return helper->GetAudioFocusGroupIdForTesting();
  }

 private:
  base::test::ScopedFeatureList scoped_feature_list_;
};

IN_PROC_BROWSER_TEST_P(WebAppAudioFocusBrowserTest, AppHasDifferentAudioFocus) {
  ASSERT_TRUE(embedded_test_server()->Start());
  GURL app_url = embedded_test_server()->GetURL(kAudioFocusTestPageURL);

  AppId app_id = InstallPWA(app_url);

  // Launch browser with media page.
  content::WebContents* tab1 = AddTestPageTabAtIndex(0);

  // Start the test page playing.
  EXPECT_TRUE(StartPlaying(tab1));

  // Launch a second tab in the browser.
  content::WebContents* tab2 = AddTestPageTabAtIndex(0);

  // Start the test page playing and check that both tabs now have focus.
  EXPECT_TRUE(StartPlaying(tab2));
  EXPECT_FALSE(IsPaused(tab1));

  // Check that the two tabs have no group id.
  EXPECT_EQ(base::UnguessableToken::Null(), GetAudioFocusGroupId(tab1));
  EXPECT_EQ(base::UnguessableToken::Null(), GetAudioFocusGroupId(tab2));

  // Launch the PWA.
  Browser* app_browser = LaunchWebAppBrowserAndWait(app_id);
  content::WebContents* web_contents =
      app_browser->tab_strip_model()->GetActiveWebContents();
  EXPECT_TRUE(content::WaitForLoadStop(web_contents));

  // Start the PWA playing and check that it has a group id.
  EXPECT_TRUE(StartPlaying(web_contents));
  const base::UnguessableToken& group_id = GetAudioFocusGroupId(web_contents);
  EXPECT_NE(base::UnguessableToken::Null(), group_id);

  // Check that the hosted app took audio focus from the browser tabs.
  EXPECT_TRUE(WaitForPause(tab1));
  EXPECT_TRUE(WaitForPause(tab2));

  // Open a new window from the PWA. It will open in the browser so it should
  // have no group id.
  {
    content::WebContents* new_contents;
    OpenWindow(web_contents, app_url, true, true, &new_contents);
    EXPECT_EQ(base::UnguessableToken::Null(),
              GetAudioFocusGroupId(new_contents));
  }

  // Navigate inside the PWA and make sure we keep the same group id.
  {
    std::string new_query_string = "t=1";
    url::Component new_query(0, new_query_string.length());
    url::Replacements<char> replacements;
    replacements.SetQuery(new_query_string.c_str(), new_query);
    GURL new_url =
        web_contents->GetLastCommittedURL().ReplaceComponents(replacements);
    NavigateInRenderer(web_contents, new_url);
    EXPECT_EQ(group_id, GetAudioFocusGroupId(web_contents));
  }

  // Launch a second window for the PWA. It should have the same group id.
  {
    Browser* second_app_browser = LaunchWebAppBrowserAndWait(app_id);

    content::WebContents* new_contents =
        second_app_browser->tab_strip_model()->GetActiveWebContents();
    EXPECT_TRUE(content::WaitForLoadStop(new_contents));

    EXPECT_EQ(group_id, GetAudioFocusGroupId(new_contents));
  }

  // Clone the web contents and make sure it has a different group id since it
  // is not in an app window.
  {
    std::unique_ptr<content::WebContents> new_contents = web_contents->Clone();
    EXPECT_TRUE(content::WaitForLoadStop(new_contents.get()));
    EXPECT_EQ(base::UnguessableToken::Null(),
              GetAudioFocusGroupId(new_contents.get()));
  }

  // Navigate away and check that the group id is still the same because we are
  // part of the same window.
  NavigateInRenderer(web_contents, GURL("https://www.example.com"));
  EXPECT_EQ(group_id, GetAudioFocusGroupId(web_contents));
}

IN_PROC_BROWSER_TEST_P(WebAppAudioFocusBrowserTest, WebAppHasSameAudioFocus) {
  ASSERT_TRUE(embedded_test_server()->Start());
  GURL app_url = embedded_test_server()->GetURL(kAudioFocusTestPageURL);

  AppId app_id = InstallPWA(app_url);

  ui_test_utils::NavigateToURL(browser(), app_url);
  content::WebContents* web_contents =
      browser()->tab_strip_model()->GetActiveWebContents();
  EXPECT_TRUE(content::WaitForLoadStop(web_contents));

  EXPECT_EQ(base::UnguessableToken::Null(), GetAudioFocusGroupId(web_contents));
}

INSTANTIATE_TEST_SUITE_P(All,
                         WebAppAudioFocusBrowserTest,
                         ::testing::Values(ProviderType::kBookmarkApps,
                                           ProviderType::kWebApps),
                         ProviderTypeParamToString);

}  // namespace web_app
