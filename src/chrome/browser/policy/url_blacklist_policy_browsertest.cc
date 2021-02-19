// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/strings/string16.h"
#include "base/values.h"
#include "build/build_config.h"
#include "chrome/browser/apps/app_service/app_launch_params.h"
#include "chrome/browser/apps/app_service/app_service_proxy_factory.h"
#include "chrome/browser/policy/policy_test_utils.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/ui/browser.h"
#include "chrome/browser/ui/browser_commands.h"
#include "chrome/test/base/ui_test_utils.h"
#include "components/policy/core/common/policy_map.h"
#include "components/policy/core/common/policy_pref_names.h"
#include "components/policy/core/common/policy_types.h"
#include "components/policy/policy_constants.h"
#include "components/prefs/pref_service.h"
#include "content/public/test/browser_test.h"
#include "content/public/test/browser_test_utils.h"
#include "net/test/embedded_test_server/embedded_test_server.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

#if !defined(OS_MAC)
#include "extensions/browser/app_window/app_window.h"
#include "ui/base/window_open_disposition.h"
#endif

using content::BrowserThread;

namespace policy {

namespace {

// Verifies that the given url |spec| can be opened. This assumes that |spec|
// points at empty.html in the test data dir.
void CheckCanOpenURL(Browser* browser, const std::string& spec) {
  GURL url(spec);
  ui_test_utils::NavigateToURL(browser, url);
  content::WebContents* contents =
      browser->tab_strip_model()->GetActiveWebContents();
  EXPECT_EQ(url, contents->GetURL());

  base::string16 blocked_page_title;
  if (url.has_host()) {
    blocked_page_title = base::UTF8ToUTF16(url.host());
  } else {
    // Local file paths show the full URL.
    blocked_page_title = base::UTF8ToUTF16(url.spec());
  }
  EXPECT_NE(blocked_page_title, contents->GetTitle());
}

}  //  namespace

IN_PROC_BROWSER_TEST_F(PolicyTest, URLBlacklist) {
  // Checks that URLs can be blacklisted, and that exceptions can be made to
  // the blacklist.

  ASSERT_TRUE(embedded_test_server()->Start());

  const std::string kURLS[] = {
      embedded_test_server()->GetURL("aaa.com", "/empty.html").spec(),
      embedded_test_server()->GetURL("bbb.com", "/empty.html").spec(),
      embedded_test_server()->GetURL("sub.bbb.com", "/empty.html").spec(),
      embedded_test_server()->GetURL("bbb.com", "/policy/blank.html").spec(),
      embedded_test_server()->GetURL("bbb.com.", "/policy/blank.html").spec(),
  };

  // Verify that "bbb.com" opens before applying the blacklist.
  CheckCanOpenURL(browser(), kURLS[1]);

  // Set a blacklist.
  base::ListValue blacklist;
  blacklist.AppendString("bbb.com");
  PolicyMap policies;
  policies.Set(key::kURLBlacklist, POLICY_LEVEL_MANDATORY, POLICY_SCOPE_USER,
               POLICY_SOURCE_CLOUD, blacklist.Clone(), nullptr);
  UpdateProviderPolicy(policies);
  FlushBlacklistPolicy();
  // All bbb.com URLs are blocked, and "aaa.com" is still unblocked.
  CheckCanOpenURL(browser(), kURLS[0]);
  for (size_t i = 1; i < base::size(kURLS); ++i)
    CheckURLIsBlocked(browser(), kURLS[i]);

  // Whitelist some sites of bbb.com.
  base::ListValue whitelist;
  whitelist.AppendString("sub.bbb.com");
  whitelist.AppendString("bbb.com/policy");
  policies.Set(key::kURLWhitelist, POLICY_LEVEL_MANDATORY, POLICY_SCOPE_USER,
               POLICY_SOURCE_CLOUD, whitelist.Clone(), nullptr);
  UpdateProviderPolicy(policies);
  FlushBlacklistPolicy();
  CheckURLIsBlocked(browser(), kURLS[1]);
  CheckCanOpenURL(browser(), kURLS[2]);
  CheckCanOpenURL(browser(), kURLS[3]);
  CheckCanOpenURL(browser(), kURLS[4]);
}

IN_PROC_BROWSER_TEST_F(PolicyTest, URLBlacklistIncognito) {
  // Checks that URLs can be blacklisted, and that exceptions can be made to
  // the blacklist.

  Browser* incognito_browser =
      OpenURLOffTheRecord(browser()->profile(), GURL("about:blank"));

  ASSERT_TRUE(embedded_test_server()->Start());

  const std::string kURLS[] = {
      embedded_test_server()->GetURL("aaa.com", "/empty.html").spec(),
      embedded_test_server()->GetURL("bbb.com", "/empty.html").spec(),
      embedded_test_server()->GetURL("sub.bbb.com", "/empty.html").spec(),
      embedded_test_server()->GetURL("bbb.com", "/policy/blank.html").spec(),
      embedded_test_server()->GetURL("bbb.com.", "/policy/blank.html").spec(),
  };

  // Verify that "bbb.com" opens before applying the blacklist.
  CheckCanOpenURL(incognito_browser, kURLS[1]);

  // Set a blacklist.
  base::ListValue blacklist;
  blacklist.AppendString("bbb.com");
  PolicyMap policies;
  policies.Set(key::kURLBlacklist, POLICY_LEVEL_MANDATORY, POLICY_SCOPE_USER,
               POLICY_SOURCE_CLOUD, blacklist.Clone(), nullptr);
  UpdateProviderPolicy(policies);
  FlushBlacklistPolicy();
  // All bbb.com URLs are blocked, and "aaa.com" is still unblocked.
  CheckCanOpenURL(incognito_browser, kURLS[0]);
  for (size_t i = 1; i < base::size(kURLS); ++i)
    CheckURLIsBlocked(incognito_browser, kURLS[i]);

  // Whitelist some sites of bbb.com.
  base::ListValue whitelist;
  whitelist.AppendString("sub.bbb.com");
  whitelist.AppendString("bbb.com/policy");
  policies.Set(key::kURLWhitelist, POLICY_LEVEL_MANDATORY, POLICY_SCOPE_USER,
               POLICY_SOURCE_CLOUD, whitelist.Clone(), nullptr);
  UpdateProviderPolicy(policies);
  FlushBlacklistPolicy();
  CheckURLIsBlocked(incognito_browser, kURLS[1]);
  CheckCanOpenURL(incognito_browser, kURLS[2]);
  CheckCanOpenURL(incognito_browser, kURLS[3]);
  CheckCanOpenURL(incognito_browser, kURLS[4]);
}

IN_PROC_BROWSER_TEST_F(PolicyTest, URLBlacklistAndWhitelist) {
  // Regression test for http://crbug.com/755256. Blacklisting * and
  // whitelisting an origin should work.

  ASSERT_TRUE(embedded_test_server()->Start());

  base::ListValue blacklist;
  blacklist.AppendString("*");
  PolicyMap policies;
  policies.Set(key::kURLBlacklist, POLICY_LEVEL_MANDATORY, POLICY_SCOPE_USER,
               POLICY_SOURCE_CLOUD, blacklist.Clone(), nullptr);

  base::ListValue whitelist;
  whitelist.AppendString("aaa.com");
  policies.Set(key::kURLWhitelist, POLICY_LEVEL_MANDATORY, POLICY_SCOPE_USER,
               POLICY_SOURCE_CLOUD, whitelist.Clone(), nullptr);
  UpdateProviderPolicy(policies);
  FlushBlacklistPolicy();
  CheckCanOpenURL(
      browser(),
      embedded_test_server()->GetURL("aaa.com", "/empty.html").spec());
}

IN_PROC_BROWSER_TEST_F(PolicyTest, URLBlacklistSubresources) {
  // Checks that an image with a blacklisted URL is loaded, but an iframe with a
  // blacklisted URL is not.

  ASSERT_TRUE(embedded_test_server()->Start());

  GURL main_url =
      embedded_test_server()->GetURL("/policy/blacklist-subresources.html");
  GURL image_url = embedded_test_server()->GetURL("/policy/pixel.png");
  GURL subframe_url = embedded_test_server()->GetURL("/policy/blank.html");

  // Set a blacklist containing the image and the iframe which are used by the
  // main document.
  base::ListValue blacklist;
  blacklist.AppendString(image_url.spec().c_str());
  blacklist.AppendString(subframe_url.spec().c_str());
  PolicyMap policies;
  policies.Set(key::kURLBlacklist, POLICY_LEVEL_MANDATORY, POLICY_SCOPE_USER,
               POLICY_SOURCE_CLOUD, blacklist.Clone(), nullptr);
  UpdateProviderPolicy(policies);
  FlushBlacklistPolicy();

  std::string blacklisted_image_load_result;
  ui_test_utils::NavigateToURL(browser(), main_url);
  ASSERT_TRUE(content::ExecuteScriptAndExtractString(
      browser()->tab_strip_model()->GetActiveWebContents(),
      "window.domAutomationController.send(imageLoadResult)",
      &blacklisted_image_load_result));
  EXPECT_EQ("success", blacklisted_image_load_result);

  std::string blacklisted_iframe_load_result;
  ui_test_utils::NavigateToURL(browser(), main_url);
  ASSERT_TRUE(content::ExecuteScriptAndExtractString(
      browser()->tab_strip_model()->GetActiveWebContents(),
      "window.domAutomationController.send(iframeLoadResult)",
      &blacklisted_iframe_load_result));
  EXPECT_EQ("error", blacklisted_iframe_load_result);
}

IN_PROC_BROWSER_TEST_F(PolicyTest, URLBlacklistClientRedirect) {
  // Checks that a client side redirect to a blacklisted URL is blocked.
  ASSERT_TRUE(embedded_test_server()->Start());

  GURL redirected_url =
      embedded_test_server()->GetURL("/policy/blacklist-redirect.html");
  GURL first_url = embedded_test_server()->GetURL("/client-redirect?" +
                                                  redirected_url.spec());

  // There are two navigations: one when loading client-redirect.html and
  // another when the document redirects using http-equiv="refresh".
  ui_test_utils::NavigateToURLBlockUntilNavigationsComplete(browser(),
                                                            first_url, 2);
  EXPECT_EQ(base::ASCIIToUTF16("Redirected!"),
            browser()->tab_strip_model()->GetActiveWebContents()->GetTitle());

  base::ListValue blacklist;
  blacklist.AppendString(redirected_url.spec().c_str());
  PolicyMap policies;
  policies.Set(key::kURLBlacklist, POLICY_LEVEL_MANDATORY, POLICY_SCOPE_USER,
               POLICY_SOURCE_CLOUD, blacklist.Clone(), nullptr);
  UpdateProviderPolicy(policies);
  FlushBlacklistPolicy();

  ui_test_utils::NavigateToURL(browser(), first_url);
  content::WaitForLoadStop(
      browser()->tab_strip_model()->GetActiveWebContents());
  EXPECT_NE(base::ASCIIToUTF16("Redirected!"),
            browser()->tab_strip_model()->GetActiveWebContents()->GetTitle());
}

IN_PROC_BROWSER_TEST_F(PolicyTest, URLBlacklistServerRedirect) {
  // Checks that a server side redirect to a blacklisted URL is blocked.
  ASSERT_TRUE(embedded_test_server()->Start());

  GURL redirected_url =
      embedded_test_server()->GetURL("/policy/blacklist-redirect.html");
  GURL first_url = embedded_test_server()->GetURL("/server-redirect?" +
                                                  redirected_url.spec());

  ui_test_utils::NavigateToURL(browser(), first_url);
  content::WaitForLoadStop(
      browser()->tab_strip_model()->GetActiveWebContents());
  EXPECT_EQ(base::ASCIIToUTF16("Redirected!"),
            browser()->tab_strip_model()->GetActiveWebContents()->GetTitle());

  base::ListValue blacklist;
  blacklist.AppendString(redirected_url.spec().c_str());
  PolicyMap policies;
  policies.Set(key::kURLBlacklist, POLICY_LEVEL_MANDATORY, POLICY_SCOPE_USER,
               POLICY_SOURCE_CLOUD, blacklist.Clone(), nullptr);
  UpdateProviderPolicy(policies);
  FlushBlacklistPolicy();

  ui_test_utils::NavigateToURL(browser(), first_url);
  content::WaitForLoadStop(
      browser()->tab_strip_model()->GetActiveWebContents());
  EXPECT_NE(base::ASCIIToUTF16("Redirected!"),
            browser()->tab_strip_model()->GetActiveWebContents()->GetTitle());
}

#if defined(OS_MAC)
// http://crbug.com/339240
#define MAYBE_FileURLBlacklist DISABLED_FileURLBlacklist
#else
#define MAYBE_FileURLBlacklist FileURLBlacklist
#endif
IN_PROC_BROWSER_TEST_F(PolicyTest, MAYBE_FileURLBlacklist) {
  // Check that FileURLs can be blacklisted and DisabledSchemes works together
  // with URLblacklisting and URLwhitelisting.

  base::FilePath test_path;
  GetTestDataDirectory(&test_path);
  const std::string base_path = "file://" + test_path.AsUTF8Unsafe() + "/";
  const std::string folder_path = base_path + "apptest/";
  const std::string file_path1 = base_path + "title1.html";
  const std::string file_path2 = folder_path + "basic.html";

  CheckCanOpenURL(browser(), file_path1);
  CheckCanOpenURL(browser(), file_path2);

  // Set a blacklist for all the files.
  base::ListValue blacklist;
  blacklist.AppendString("file://*");
  PolicyMap policies;
  policies.Set(key::kURLBlacklist, POLICY_LEVEL_MANDATORY, POLICY_SCOPE_USER,
               POLICY_SOURCE_CLOUD, blacklist.Clone(), nullptr);
  UpdateProviderPolicy(policies);
  FlushBlacklistPolicy();

  CheckURLIsBlocked(browser(), file_path1);
  CheckURLIsBlocked(browser(), file_path2);

  // Replace the URLblacklist with disabling the file scheme.
  blacklist.Remove(base::Value("file://*"), nullptr);
  policies.Set(key::kURLBlacklist, POLICY_LEVEL_MANDATORY, POLICY_SCOPE_USER,
               POLICY_SOURCE_CLOUD, blacklist.Clone(), nullptr);
  UpdateProviderPolicy(policies);
  FlushBlacklistPolicy();

  PrefService* prefs = browser()->profile()->GetPrefs();
  const base::ListValue* list_url = prefs->GetList(policy_prefs::kUrlBlacklist);
  EXPECT_EQ(list_url->Find(base::Value("file://*")), list_url->end());

  base::ListValue disabledscheme;
  disabledscheme.AppendString("file");
  policies.Set(key::kDisabledSchemes, POLICY_LEVEL_MANDATORY, POLICY_SCOPE_USER,
               POLICY_SOURCE_CLOUD, disabledscheme.Clone(), nullptr);
  UpdateProviderPolicy(policies);
  FlushBlacklistPolicy();

  list_url = prefs->GetList(policy_prefs::kUrlBlacklist);
  EXPECT_NE(list_url->Find(base::Value("file://*")), list_url->end());

  // Whitelist one folder and blacklist an another just inside.
  base::ListValue whitelist;
  whitelist.AppendString(base_path);
  policies.Set(key::kURLWhitelist, POLICY_LEVEL_MANDATORY, POLICY_SCOPE_USER,
               POLICY_SOURCE_CLOUD, whitelist.Clone(), nullptr);
  blacklist.AppendString(folder_path);
  policies.Set(key::kURLBlacklist, POLICY_LEVEL_MANDATORY, POLICY_SCOPE_USER,
               POLICY_SOURCE_CLOUD, blacklist.Clone(), nullptr);
  UpdateProviderPolicy(policies);
  FlushBlacklistPolicy();

  CheckCanOpenURL(browser(), file_path1);
  CheckURLIsBlocked(browser(), file_path2);
}

}  // namespace policy
