// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string.h>

#include "base/command_line.h"
#include "base/run_loop.h"
#include "base/strings/utf_string_conversions.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "base/time/time.h"
#include "base/timer/timer.h"
#include "build/build_config.h"
#include "chrome/browser/dom_distiller/dom_distiller_service_factory.h"
#include "chrome/browser/dom_distiller/tab_utils.h"
#include "chrome/browser/ssl/security_state_tab_helper.h"
#include "chrome/browser/ui/browser.h"
#include "chrome/browser/ui/tabs/tab_strip_model.h"
#include "chrome/test/base/in_process_browser_test.h"
#include "chrome/test/base/ui_test_utils.h"
#include "components/dom_distiller/content/browser/distillable_page_utils.h"
#include "components/dom_distiller/content/browser/distiller_javascript_utils.h"
#include "components/dom_distiller/content/browser/test_distillability_observer.h"
#include "components/dom_distiller/core/dom_distiller_features.h"
#include "components/dom_distiller/core/dom_distiller_service.h"
#include "components/dom_distiller/core/dom_distiller_switches.h"
#include "components/dom_distiller/core/task_tracker.h"
#include "components/dom_distiller/core/url_constants.h"
#include "components/dom_distiller/core/url_utils.h"
#include "components/favicon/content/content_favicon_driver.h"
#include "components/favicon/core/favicon_driver_observer.h"
#include "components/security_state/core/security_state.h"
#include "content/public/browser/navigation_entry.h"
#include "content/public/browser/render_frame_host.h"
#include "content/public/browser/render_process_host.h"
#include "content/public/browser/render_view_host.h"
#include "content/public/browser/ssl_status.h"
#include "content/public/browser/web_contents.h"
#include "content/public/browser/web_contents_observer.h"
#include "content/public/common/content_switches.h"
#include "content/public/common/isolated_world_ids.h"
#include "content/public/test/back_forward_cache_util.h"
#include "content/public/test/browser_test.h"
#include "content/public/test/browser_test_utils.h"
#include "content/public/test/test_utils.h"
#include "net/test/embedded_test_server/embedded_test_server.h"
#include "net/test/embedded_test_server/request_handler_util.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/web_preferences/web_preferences.h"
#include "ui/gfx/image/image_unittest_util.h"

namespace dom_distiller {
namespace {

const char* kSimpleArticlePath = "/dom_distiller/simple_article.html";
const char* kOriginalArticleTitle = "Test Page Title";
const char* kExpectedArticleHeading = "Test Page Title";
#if defined(OS_ANDROID)
const char* kExpectedDocumentTitle = "Test Page Title";
#else   // Desktop. This test is in chrome/ and is not run on iOS.
const char* kExpectedDocumentTitle = "Test Page Title - Reader Mode";
#endif  // defined(OS_ANDROID)
const char* kDistillablePageHistogram =
    "DomDistiller.Time.ActivelyViewingArticleBeforeDistilling";
const char* kDistilledPageHistogram =
    "DomDistiller.Time.ActivelyViewingReaderModePage";

std::unique_ptr<content::WebContents> NewContentsWithSameParamsAs(
    content::WebContents* source_web_contents) {
  content::WebContents::CreateParams create_params(
      source_web_contents->GetBrowserContext());
  auto new_web_contents = content::WebContents::Create(create_params);
  DCHECK(new_web_contents);
  return new_web_contents;
}

// Helper class that blocks test execution until |observed_contents| enters a
// certain state. Subclasses specify the precise state by calling
// |new_url_loaded_runner_|.QuitClosure().Run() when |observed_contents| is
// ready.
class NavigationObserver : public content::WebContentsObserver {
 public:
  explicit NavigationObserver(content::WebContents* observed_contents) {
    content::WebContentsObserver::Observe(observed_contents);
  }

  void WaitUntilFinishedLoading() { new_url_loaded_runner_.Run(); }

 protected:
  base::RunLoop new_url_loaded_runner_;
};

class OriginalPageNavigationObserver : public NavigationObserver {
 public:
  using NavigationObserver::NavigationObserver;

  void DidFinishLoad(content::RenderFrameHost* render_frame_host,
                     const GURL& validated_url) override {
    if (!render_frame_host->GetParent())
      new_url_loaded_runner_.QuitClosure().Run();
  }
};

// DistilledPageObserver is used to detect if a distilled page has
// finished loading. This is done by checking how many times the title has
// been set rather than using "DidFinishLoad" directly due to the content
// being set by JavaScript.
class DistilledPageObserver : public NavigationObserver {
 public:
  explicit DistilledPageObserver(content::WebContents* observed_contents)
      : NavigationObserver(observed_contents),
        title_set_count_(0),
        loaded_distiller_page_(false) {}

  void DidFinishLoad(content::RenderFrameHost* render_frame_host,
                     const GURL& validated_url) override {
    if (!render_frame_host->GetParent() &&
        validated_url.scheme() == kDomDistillerScheme) {
      loaded_distiller_page_ = true;
      MaybeNotifyLoaded();
    }
  }

  void TitleWasSet(content::NavigationEntry* entry) override {
    // The title will be set twice on distilled pages; once for the placeholder
    // and once when the distillation has finished. Watch for the second time
    // as a signal that the JavaScript that sets the content has run.
    title_set_count_++;
    MaybeNotifyLoaded();
  }

 private:
  int title_set_count_;
  bool loaded_distiller_page_;

  // DidFinishLoad() can come after the two title settings.
  void MaybeNotifyLoaded() {
    if (title_set_count_ >= 2 && loaded_distiller_page_) {
      new_url_loaded_runner_.QuitClosure().Run();
    }
  }
};

// FaviconUpdateWaiter waits for favicons to be changed after navigation.
// TODO(1064318): Combine with FaviconUpdateWaiter in
// chrome/browser/chrome_service_worker_browsertest.cc.
class FaviconUpdateWaiter : public favicon::FaviconDriverObserver {
 public:
  explicit FaviconUpdateWaiter(content::WebContents* web_contents) {
    scoped_observer_.Add(
        favicon::ContentFaviconDriver::FromWebContents(web_contents));
  }
  ~FaviconUpdateWaiter() override = default;

  void Wait() {
    if (updated_)
      return;

    base::RunLoop run_loop;
    quit_closure_ = run_loop.QuitClosure();
    run_loop.Run();
  }

  void StopObserving() { scoped_observer_.RemoveAll(); }

 private:
  void OnFaviconUpdated(favicon::FaviconDriver* favicon_driver,
                        NotificationIconType notification_icon_type,
                        const GURL& icon_url,
                        bool icon_url_changed,
                        const gfx::Image& image) override {
    updated_ = true;
    if (!quit_closure_.is_null())
      std::move(quit_closure_).Run();
  }

  bool updated_ = false;
  ScopedObserver<favicon::FaviconDriver, favicon::FaviconDriverObserver>
      scoped_observer_{this};
  base::OnceClosure quit_closure_;

  DISALLOW_COPY_AND_ASSIGN(FaviconUpdateWaiter);
};

class DomDistillerTabUtilsBrowserTest : public InProcessBrowserTest {
 public:
  void SetUpOnMainThread() override {
    if (!DistillerJavaScriptWorldIdIsSet()) {
      SetDistillerJavaScriptWorldId(content::ISOLATED_WORLD_ID_CONTENT_END);
    }
    ASSERT_TRUE(https_server_->Start());
    article_url_ = https_server_->GetURL(kSimpleArticlePath);
  }

  void SetUpCommandLine(base::CommandLine* command_line) override {
    command_line->AppendSwitch(switches::kEnableDomDistiller);
  }

 protected:
  DomDistillerTabUtilsBrowserTest() {
    feature_list_.InitAndEnableFeature(dom_distiller::kReaderMode);
  }

  void SetUpInProcessBrowserTestFixture() override {
    https_server_.reset(
        new net::EmbeddedTestServer(net::EmbeddedTestServer::TYPE_HTTPS));
    https_server_->ServeFilesFromSourceDirectory(GetChromeTestDataDir());
  }
  const GURL& article_url() const { return article_url_; }

  std::string GetDocumentTitle(content::WebContents* web_contents) const {
    return content::ExecuteScriptAndGetValue(web_contents->GetMainFrame(),
                                             "document.title")
        .GetString();
  }

  std::string GetArticleHeading(content::WebContents* web_contents) const {
    return content::ExecuteScriptAndGetValue(
               web_contents->GetMainFrame(),
               "document.getElementById('title-holder').textContent")
        .GetString();
  }

  std::unique_ptr<net::EmbeddedTestServer> https_server_;

 private:
  base::test::ScopedFeatureList feature_list_;
  GURL article_url_;
};

IN_PROC_BROWSER_TEST_F(DomDistillerTabUtilsBrowserTest,
                       DistillCurrentPageSwapsWebContents) {
  content::WebContents* initial_web_contents =
      browser()->tab_strip_model()->GetActiveWebContents();
  TestDistillabilityObserver distillability_observer(initial_web_contents);
  DistillabilityResult expected_result;
  expected_result.is_distillable = true;
  expected_result.is_last = false;
  expected_result.is_mobile_friendly = false;

  // This blocks until the navigation has completely finished.
  ui_test_utils::NavigateToURL(browser(), article_url());
  // This blocks until the page is found to be distillable.
  distillability_observer.WaitForResult(expected_result);

  DistillCurrentPageAndView(initial_web_contents);

  // Retrieve new web contents and wait for it to finish loading.
  content::WebContents* after_web_contents =
      browser()->tab_strip_model()->GetActiveWebContents();
  ASSERT_NE(after_web_contents, nullptr);
  DistilledPageObserver(after_web_contents).WaitUntilFinishedLoading();

  // Verify the new URL is showing distilled content in a new WebContents.
  EXPECT_NE(initial_web_contents, after_web_contents);
  EXPECT_TRUE(
      after_web_contents->GetLastCommittedURL().SchemeIs(kDomDistillerScheme));
  EXPECT_EQ(kExpectedDocumentTitle, GetDocumentTitle(after_web_contents));
  EXPECT_EQ(kExpectedArticleHeading, GetArticleHeading(after_web_contents));
}

// TODO(1061928): Make this test more robust by using a TestMockTimeTaskRunner
// and a test TickClock. This would require having UMAHelper be an object
// so that it can hold a TickClock reference.
IN_PROC_BROWSER_TEST_F(DomDistillerTabUtilsBrowserTest, UMATimesAreLogged) {
  base::HistogramTester histogram_tester;

  content::WebContents* initial_web_contents =
      browser()->tab_strip_model()->GetActiveWebContents();
  TestDistillabilityObserver distillability_observer(initial_web_contents);
  DistillabilityResult expected_result;
  expected_result.is_distillable = true;
  expected_result.is_last = false;
  expected_result.is_mobile_friendly = false;

  // This blocks until the navigation has completely finished.
  ui_test_utils::NavigateToURL(browser(), article_url());
  // This blocks until the page is found to be distillable.
  distillability_observer.WaitForResult(expected_result);

  // No UMA logged for distillable or distilled yet.
  histogram_tester.ExpectTotalCount(kDistillablePageHistogram, 0);
  histogram_tester.ExpectTotalCount(kDistilledPageHistogram, 0);

  DistillCurrentPageAndView(initial_web_contents);

  // UMA should now exist for the distillable page because we distilled it.
  histogram_tester.ExpectTotalCount(kDistillablePageHistogram, 1);

  // Distilled page UMA isn't logged until we leave that page.
  histogram_tester.ExpectTotalCount(kDistilledPageHistogram, 0);

  // Go back to the article, check UMA exists for distilled page now.
  ui_test_utils::NavigateToURL(browser(), article_url());
  histogram_tester.ExpectTotalCount(kDistilledPageHistogram, 1);
  // However, there should not be a second distillable histogram.
  histogram_tester.ExpectTotalCount(kDistillablePageHistogram, 1);
}

IN_PROC_BROWSER_TEST_F(DomDistillerTabUtilsBrowserTest,
                       DistillAndViewCreatesNewWebContentsAndPreservesOld) {
  content::WebContents* source_web_contents =
      browser()->tab_strip_model()->GetActiveWebContents();

  // This blocks until the navigation has completely finished.
  ui_test_utils::NavigateToURL(browser(), article_url());

  // Create destination WebContents and add it to the tab strip.
  browser()->tab_strip_model()->AppendWebContents(
      NewContentsWithSameParamsAs(source_web_contents),
      /* foreground = */ true);
  content::WebContents* destination_web_contents =
      browser()->tab_strip_model()->GetWebContentsAt(1);

  DistillAndView(source_web_contents, destination_web_contents);
  DistilledPageObserver(destination_web_contents).WaitUntilFinishedLoading();

  // Verify that the source WebContents is showing the original article.
  EXPECT_EQ(article_url(), source_web_contents->GetLastCommittedURL());
  EXPECT_EQ(kOriginalArticleTitle, GetDocumentTitle(source_web_contents));

  // Verify the destination WebContents is showing distilled content.
  EXPECT_TRUE(destination_web_contents->GetLastCommittedURL().SchemeIs(
      kDomDistillerScheme));
  EXPECT_EQ(kExpectedDocumentTitle, GetDocumentTitle(destination_web_contents));
  EXPECT_EQ(kExpectedArticleHeading,
            GetArticleHeading(destination_web_contents));

  content::WebContentsDestroyedWatcher destroyed_watcher(
      destination_web_contents);
  browser()->tab_strip_model()->CloseWebContentsAt(1, 0);
  destroyed_watcher.Wait();
}

IN_PROC_BROWSER_TEST_F(DomDistillerTabUtilsBrowserTest, ToggleOriginalPage) {
  content::WebContents* source_web_contents =
      browser()->tab_strip_model()->GetActiveWebContents();

  // This blocks until the navigation has completely finished.
  ui_test_utils::NavigateToURL(browser(), article_url());

  // Create and navigate to the distilled page.
  browser()->tab_strip_model()->AppendWebContents(
      NewContentsWithSameParamsAs(source_web_contents),
      /* foreground = */ true);
  content::WebContents* destination_web_contents =
      browser()->tab_strip_model()->GetWebContentsAt(1);

  DistillAndView(source_web_contents, destination_web_contents);
  DistilledPageObserver(destination_web_contents).WaitUntilFinishedLoading();
  ASSERT_TRUE(url_utils::IsDistilledPage(
      destination_web_contents->GetLastCommittedURL()));

  // Now return to the original page.
  ReturnToOriginalPage(destination_web_contents);
  OriginalPageNavigationObserver(destination_web_contents)
      .WaitUntilFinishedLoading();
  EXPECT_EQ(source_web_contents->GetLastCommittedURL(),
            destination_web_contents->GetLastCommittedURL());
}

IN_PROC_BROWSER_TEST_F(DomDistillerTabUtilsBrowserTest,
                       DomDistillDisableForBackForwardCache) {
  content::BackForwardCacheDisabledTester tester;

  GURL url1(article_url());
  content::WebContents* initial_web_contents =
      browser()->tab_strip_model()->GetActiveWebContents();
  content::RenderFrameHost* main_frame =
      browser()->tab_strip_model()->GetActiveWebContents()->GetMainFrame();
  int process_id = main_frame->GetProcess()->GetID();
  int frame_routing_id = main_frame->GetRoutingID();
  GURL url2(https_server_->GetURL("/title1.html"));

  TestDistillabilityObserver distillability_observer(initial_web_contents);
  DistillabilityResult expected_result;
  expected_result.is_distillable = true;
  expected_result.is_last = false;
  expected_result.is_mobile_friendly = false;

  // Navigate to the page
  ui_test_utils::NavigateToURL(browser(), url1);
  distillability_observer.WaitForResult(expected_result);

  DistillCurrentPageAndView(initial_web_contents);

  // Navigate away while starting distillation. This should block bfcache.
  ui_test_utils::NavigateToURL(browser(), url2);

  EXPECT_TRUE(tester.IsDisabledForFrameWithReason(
      process_id, frame_routing_id,
      "browser::DomDistiller_SelfDeletingRequestDelegate"));
}

IN_PROC_BROWSER_TEST_F(DomDistillerTabUtilsBrowserTest, SecurityStateIsNone) {
  content::WebContents* initial_web_contents =
      browser()->tab_strip_model()->GetActiveWebContents();
  TestDistillabilityObserver distillability_observer(initial_web_contents);
  DistillabilityResult expected_result;
  expected_result.is_distillable = true;
  expected_result.is_last = false;
  expected_result.is_mobile_friendly = false;
  ui_test_utils::NavigateToURL(browser(), article_url());
  distillability_observer.WaitForResult(expected_result);

  // Check security state is not NONE.
  SecurityStateTabHelper* helper =
      SecurityStateTabHelper::FromWebContents(initial_web_contents);
  ASSERT_NE(security_state::NONE, helper->GetSecurityLevel());

  DistillCurrentPageAndView(initial_web_contents);
  content::WebContents* after_web_contents =
      browser()->tab_strip_model()->GetActiveWebContents();
  DistilledPageObserver(after_web_contents).WaitUntilFinishedLoading();

  // Now security state should be NONE.
  helper = SecurityStateTabHelper::FromWebContents(after_web_contents);
  ASSERT_EQ(security_state::NONE, helper->GetSecurityLevel());
}

IN_PROC_BROWSER_TEST_F(DomDistillerTabUtilsBrowserTest,
                       FaviconFromOriginalPage) {
  content::WebContents* initial_web_contents =
      browser()->tab_strip_model()->GetActiveWebContents();

  TestDistillabilityObserver distillability_observer(initial_web_contents);
  DistillabilityResult expected_result;
  expected_result.is_distillable = true;
  expected_result.is_last = false;
  expected_result.is_mobile_friendly = false;
  FaviconUpdateWaiter waiter(initial_web_contents);

  ui_test_utils::NavigateToURL(browser(), article_url());
  // Ensure the favicon is loaded and the distillability result has also
  // loaded before proceeding with the test.
  waiter.Wait();
  distillability_observer.WaitForResult(expected_result);

  gfx::Image article_favicon = browser()->GetCurrentPageIcon();
  // Remove the FaviconUpdateWaiter because we are done with
  // initial_web_contents.
  waiter.StopObserving();

  DistillCurrentPageAndView(initial_web_contents);
  content::WebContents* after_web_contents =
      browser()->tab_strip_model()->GetActiveWebContents();
  ASSERT_NE(after_web_contents, nullptr);
  DistilledPageObserver(after_web_contents).WaitUntilFinishedLoading();

  gfx::Image distilled_favicon = browser()->GetCurrentPageIcon();
  EXPECT_TRUE(gfx::test::AreImagesEqual(article_favicon, distilled_favicon));
}

#if !defined(OS_ANDROID)
class DistilledPageImageLoadWaiter {
 public:
  explicit DistilledPageImageLoadWaiter(content::WebContents* contents,
                                        int ok_elem,
                                        int ok_width,
                                        int bad_elem,
                                        int bad_width)
      : contents_(contents),
        ok_elem_(ok_elem),
        ok_width_(ok_width),
        bad_elem_(bad_elem),
        bad_width_(bad_width) {}
  ~DistilledPageImageLoadWaiter() = default;
  DistilledPageImageLoadWaiter(const DistilledPageImageLoadWaiter&) = delete;
  DistilledPageImageLoadWaiter& operator=(const DistilledPageImageLoadWaiter&) =
      delete;

  void Wait() {
    base::RepeatingTimer check_timer;
    check_timer.Start(FROM_HERE, base::TimeDelta::FromMilliseconds(10), this,
                      &DistilledPageImageLoadWaiter::OnTimer);
    runner_.Run();
  }

 private:
  void OnTimer() {
    bool loaded = false;
    // Use ExecuteScriptAndExtractInt to avoid Content SecurityPolicy errors.
    // Use naturalWidth because the distiller sets the width and height
    // attributes on the img.
    // Get the good and bad imags and check they are loaded and their size.
    // If they aren't loaded or the size is wrong, stay in the loop until the
    // load completes.
    ASSERT_TRUE(content::ExecuteScriptAndExtractBool(
        contents_,
        content::JsReplace("var ok = document.getElementById('main-content')"
                           "    .getElementsByTagName('img')[$1];"
                           "var bad = document.getElementById('main-content')"
                           "    .getElementsByTagName('img')[$2];"
                           "window.domAutomationController.send("
                           "    ok.complete && ok.naturalWidth == $3 &&"
                           "    bad.complete && bad.naturalWidth == $4)",
                           ok_elem_, bad_elem_, ok_width_, bad_width_),
        &loaded));
    if (loaded)
      runner_.Quit();
  }

  content::WebContents* contents_;
  int ok_elem_;
  int ok_width_;
  int bad_elem_;
  int bad_width_;
  base::RunLoop runner_;
};

class DomDistillerTabUtilsBrowserTestInsecureContent
    : public InProcessBrowserTest {
 public:
  void SetUpOnMainThread() override {
    if (!DistillerJavaScriptWorldIdIsSet()) {
      SetDistillerJavaScriptWorldId(content::ISOLATED_WORLD_ID_CONTENT_END);
    }
    ASSERT_TRUE(https_server_->Start());
    ASSERT_TRUE(https_server_expired_->Start());
  }

  void SetUpCommandLine(base::CommandLine* command_line) override {
    command_line->AppendSwitch(switches::kEnableDomDistiller);
    command_line->AppendSwitch(switches::kAllowInsecureLocalhost);
  }

  void CheckImageWidthById(content::WebContents* contents,
                           std::string id,
                           int expected_width) {
    EXPECT_EQ(expected_width,
              content::EvalJs(contents, "document.getElementById('" + id +
                                            "').naturalWidth"));
  }

 protected:
  DomDistillerTabUtilsBrowserTestInsecureContent() {
    feature_list_.InitWithFeatures({dom_distiller::kReaderMode},
                                   {blink::features::kMixedContentAutoupgrade});
  }

  void SetUpInProcessBrowserTestFixture() override {
    https_server_.reset(
        new net::EmbeddedTestServer(net::EmbeddedTestServer::TYPE_HTTPS));
    https_server_->ServeFilesFromSourceDirectory(GetChromeTestDataDir());
    https_server_expired_.reset(
        new net::EmbeddedTestServer(net::EmbeddedTestServer::TYPE_HTTPS));
    https_server_expired_->SetSSLConfig(net::EmbeddedTestServer::CERT_EXPIRED);
    https_server_expired_->ServeFilesFromSourceDirectory(
        GetChromeTestDataDir());
  }

  std::unique_ptr<net::EmbeddedTestServer> https_server_;
  std::unique_ptr<net::EmbeddedTestServer> https_server_expired_;

 private:
  base::test::ScopedFeatureList feature_list_;
};

IN_PROC_BROWSER_TEST_F(DomDistillerTabUtilsBrowserTestInsecureContent,
                       DoesNotLoadMixedContent) {
  content::WebContents* initial_web_contents =
      browser()->tab_strip_model()->GetActiveWebContents();
  ui_test_utils::NavigateToURL(
      browser(),
      https_server_->GetURL("/dom_distiller/simple_article_mixed_image.html"));
  // Security state should be downgraded.
  SecurityStateTabHelper* helper =
      SecurityStateTabHelper::FromWebContents(initial_web_contents);
  EXPECT_EQ(security_state::WARNING, helper->GetSecurityLevel());
  EXPECT_TRUE(initial_web_contents->GetController()
                  .GetVisibleEntry()
                  ->GetSSL()
                  .content_status &
              content::SSLStatus::DISPLAYED_INSECURE_CONTENT);
  // The first image should not have loaded.
  CheckImageWidthById(initial_web_contents, "bad_image", 0);
  CheckImageWidthById(initial_web_contents, "ok_image", 276);

  // Create destination WebContents and add it to the tab strip.
  browser()->tab_strip_model()->AppendWebContents(
      NewContentsWithSameParamsAs(initial_web_contents),
      /* foreground = */ true);
  content::WebContents* destination_web_contents =
      browser()->tab_strip_model()->GetWebContentsAt(1);

  // Original page has a http image, but the page was loaded over https. It
  // isn't technically distillable because it isn't SECURE, but we will distill
  // it anyway to ensure the mixed resource is not loaded in the distilled page.
  DistillAndView(initial_web_contents, destination_web_contents);
  DistilledPageObserver(destination_web_contents).WaitUntilFinishedLoading();
  // The DistilledPageObserver looks for the title change after the JS runs,
  // but we also need to wait for the images to load since we are going to
  // be inspecting their size.
  DistilledPageImageLoadWaiter image_waiter(
      destination_web_contents,
      /* ok image */ 1, /* ok_elem's width */ 276, /* bad image */ 0,
      /* bad image's width */ 0);
  image_waiter.Wait();

  // The distilled page should not try to load insecure content.
  helper = SecurityStateTabHelper::FromWebContents(destination_web_contents);
  EXPECT_EQ(security_state::NONE, helper->GetSecurityLevel());
  EXPECT_FALSE(destination_web_contents->GetController()
                   .GetVisibleEntry()
                   ->GetSSL()
                   .content_status &
               content::SSLStatus::DISPLAYED_INSECURE_CONTENT);
}

IN_PROC_BROWSER_TEST_F(DomDistillerTabUtilsBrowserTestInsecureContent,
                       DoesNotLoadContentWithBadCert) {
  content::WebContents* initial_web_contents =
      browser()->tab_strip_model()->GetActiveWebContents();
  base::StringPairs replacement_text;
  // Create a page with an image that is loaded over a HTTPS server with invalid
  // certificate.
  replacement_text.push_back(
      make_pair("REPLACE_WITH_HOST_AND_PORT",
                https_server_expired_->host_port_pair().ToString()));
  std::string path = net::test_server::GetFilePathWithReplacements(
      "/dom_distiller/simple_article_bad_cert_image.html", replacement_text);
  ui_test_utils::NavigateToURL(browser(), https_server_->GetURL(path));
  // Should have loaded the image with the cert errors.
  SecurityStateTabHelper* helper =
      SecurityStateTabHelper::FromWebContents(initial_web_contents);
  EXPECT_TRUE(
      helper->GetVisibleSecurityState()->displayed_content_with_cert_errors);
  // Check both the good and the bad images loaded.
  CheckImageWidthById(initial_web_contents, "bad_image", 276);
  CheckImageWidthById(initial_web_contents, "ok_image", 276);

  // Create destination WebContents and add it to the tab strip.
  browser()->tab_strip_model()->AppendWebContents(
      NewContentsWithSameParamsAs(initial_web_contents),
      /* foreground = */ true);
  content::WebContents* destination_web_contents =
      browser()->tab_strip_model()->GetWebContentsAt(1);

  // Original page has broken cert image. It isn't technically distillable
  // because it isn't SECURE, but we will distill it anyway to ensure those
  // resources are not loaded in the distilled page.
  DistillAndView(initial_web_contents, destination_web_contents);
  DistilledPageObserver(destination_web_contents).WaitUntilFinishedLoading();
  DistilledPageImageLoadWaiter image_waiter(
      destination_web_contents,
      /* ok image */ 1, /* ok_elem's width */ 276, /* bad image */ 0,
      /* bad image's width */ 0);
  image_waiter.Wait();

  // Check security of the distilled page. It should not try to load the
  // image with the invalid cert.
  helper = SecurityStateTabHelper::FromWebContents(destination_web_contents);
  EXPECT_EQ(security_state::NONE, helper->GetSecurityLevel());
  EXPECT_FALSE(
      helper->GetVisibleSecurityState()->displayed_content_with_cert_errors);
}

#endif  // !defined(OS_ANDROID)

}  // namespace
}  // namespace dom_distiller
