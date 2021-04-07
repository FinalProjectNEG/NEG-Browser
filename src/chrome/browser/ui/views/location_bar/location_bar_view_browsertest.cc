// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/ui/views/location_bar/location_bar_view.h"

#include "base/bind.h"
#include "base/feature_list.h"
#include "base/files/file_path.h"
#include "base/path_service.h"
#include "base/run_loop.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "base/test/scoped_feature_list.h"
#include "chrome/browser/ssl/security_state_tab_helper.h"
#include "chrome/browser/ui/browser.h"
#include "chrome/browser/ui/browser_commands.h"
#include "chrome/browser/ui/views/frame/browser_view.h"
#include "chrome/browser/ui/views/frame/toolbar_button_provider.h"
#include "chrome/browser/ui/views/location_bar/zoom_bubble_view.h"
#include "chrome/browser/ui/views/omnibox/omnibox_view_views.h"
#include "chrome/browser/ui/views/page_action/page_action_icon_view.h"
#include "chrome/common/chrome_paths.h"
#include "chrome/test/base/in_process_browser_test.h"
#include "chrome/test/base/ui_test_utils.h"
#include "components/omnibox/browser/location_bar_model_impl.h"
#include "components/omnibox/browser/omnibox_field_trial.h"
#include "components/omnibox/common/omnibox_features.h"
#include "components/security_state/core/security_state.h"
#include "components/zoom/zoom_controller.h"
#include "content/public/browser/browser_thread.h"
#include "content/public/test/browser_test.h"
#include "net/cert/ct_policy_status.h"
#include "net/dns/mock_host_resolver.h"
#include "net/ssl/ssl_info.h"
#include "net/test/cert_test_util.h"
#include "net/test/embedded_test_server/embedded_test_server.h"
#include "net/test/test_data_directory.h"
#include "services/network/public/cpp/features.h"
#include "services/network/public/mojom/url_response_head.mojom.h"
#include "third_party/blink/public/common/page/page_zoom.h"
#include "ui/base/pointer/touch_ui_controller.h"

class LocationBarViewBrowserTest : public InProcessBrowserTest {
 public:
  LocationBarViewBrowserTest() = default;

  LocationBarView* GetLocationBarView() {
    BrowserView* browser_view =
        BrowserView::GetBrowserViewForBrowser(browser());
    return browser_view->GetLocationBarView();
  }

  PageActionIconView* GetZoomView() {
    return BrowserView::GetBrowserViewForBrowser(browser())
        ->toolbar_button_provider()
        ->GetPageActionIconView(PageActionIconType::kZoom);
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(LocationBarViewBrowserTest);
};

// Ensure the location bar decoration is added when zooming, and is removed when
// the bubble is closed, but only if zoom was reset.
IN_PROC_BROWSER_TEST_F(LocationBarViewBrowserTest, LocationBarDecoration) {
  content::WebContents* web_contents =
      browser()->tab_strip_model()->GetActiveWebContents();
  zoom::ZoomController* zoom_controller =
      zoom::ZoomController::FromWebContents(web_contents);
  PageActionIconView* zoom_view = GetZoomView();

  ASSERT_TRUE(zoom_view);
  EXPECT_FALSE(zoom_view->GetVisible());
  EXPECT_FALSE(ZoomBubbleView::GetZoomBubble());

  // Altering zoom should display a bubble. Note ZoomBubbleView closes
  // asynchronously, so precede checks with a run loop flush.
  zoom_controller->SetZoomLevel(blink::PageZoomFactorToZoomLevel(1.5));
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(zoom_view->GetVisible());
  EXPECT_TRUE(ZoomBubbleView::GetZoomBubble());

  // Close the bubble at other than 100% zoom. Icon should remain visible.
  ZoomBubbleView::CloseCurrentBubble();
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(zoom_view->GetVisible());
  EXPECT_FALSE(ZoomBubbleView::GetZoomBubble());

  // Show the bubble again.
  zoom_controller->SetZoomLevel(blink::PageZoomFactorToZoomLevel(2.0));
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(zoom_view->GetVisible());
  EXPECT_TRUE(ZoomBubbleView::GetZoomBubble());

  // Remains visible at 100% until the bubble is closed.
  zoom_controller->SetZoomLevel(blink::PageZoomFactorToZoomLevel(1.0));
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(zoom_view->GetVisible());
  EXPECT_TRUE(ZoomBubbleView::GetZoomBubble());

  // Closing at 100% hides the icon.
  ZoomBubbleView::CloseCurrentBubble();
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(zoom_view->GetVisible());
  EXPECT_FALSE(ZoomBubbleView::GetZoomBubble());
}

// Ensure that location bar bubbles close when the webcontents hides.
IN_PROC_BROWSER_TEST_F(LocationBarViewBrowserTest, BubblesCloseOnHide) {
  content::WebContents* web_contents =
      browser()->tab_strip_model()->GetActiveWebContents();
  zoom::ZoomController* zoom_controller =
      zoom::ZoomController::FromWebContents(web_contents);
  PageActionIconView* zoom_view = GetZoomView();

  ASSERT_TRUE(zoom_view);
  EXPECT_FALSE(zoom_view->GetVisible());

  zoom_controller->SetZoomLevel(blink::PageZoomFactorToZoomLevel(1.5));
  base::RunLoop().RunUntilIdle();
  EXPECT_TRUE(zoom_view->GetVisible());
  EXPECT_TRUE(ZoomBubbleView::GetZoomBubble());

  chrome::NewTab(browser());
  chrome::SelectNextTab(browser());

  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(ZoomBubbleView::GetZoomBubble());
}

class TouchLocationBarViewBrowserTest : public LocationBarViewBrowserTest {
 public:
  TouchLocationBarViewBrowserTest() = default;

 private:
  ui::TouchUiController::TouchUiScoperForTesting touch_ui_scoper_{true};
};

// Test the corners of the OmniboxViewViews do not get drawn on top of the
// rounded corners of the omnibox in touch mode.
IN_PROC_BROWSER_TEST_F(TouchLocationBarViewBrowserTest, OmniboxViewViewsSize) {
  // Make sure all the LocationBarView children are invisible. This should
  // ensure there are no trailing decorations at the end of the omnibox
  // (currently, the LocationIconView is *always* added as a leading decoration,
  // so it's not possible to test the leading side).
  views::View* omnibox_view_views = GetLocationBarView()->omnibox_view();
  for (views::View* child : GetLocationBarView()->children()) {
    if (child != omnibox_view_views)
      child->SetVisible(false);
  }

  GetLocationBarView()->Layout();
  // Check |omnibox_view_views| is not wider than the LocationBarView with its
  // rounded ends removed.
  EXPECT_LE(omnibox_view_views->width(),
            GetLocationBarView()->width() - GetLocationBarView()->height());
  // Check the trailing edge of |omnibox_view_views| does not exceed the
  // trailing edge of the LocationBarView with its endcap removed.
  EXPECT_LE(omnibox_view_views->bounds().right(),
            GetLocationBarView()->GetLocalBoundsWithoutEndcaps().right());
}

// Make sure the IME autocomplete selection text is positioned correctly when
// there are no trailing decorations.
IN_PROC_BROWSER_TEST_F(TouchLocationBarViewBrowserTest,
                       IMEInlineAutocompletePosition) {
  // Make sure all the LocationBarView children are invisible. This should
  // ensure there are no trailing decorations at the end of the omnibox.
  OmniboxViewViews* omnibox_view_views = GetLocationBarView()->omnibox_view();
  views::Label* ime_inline_autocomplete_view =
      GetLocationBarView()->ime_inline_autocomplete_view_;
  for (views::View* child : GetLocationBarView()->children()) {
    if (child != omnibox_view_views)
      child->SetVisible(false);
  }
  omnibox_view_views->SetText(base::UTF8ToUTF16("谷"));
  GetLocationBarView()->SetImeInlineAutocompletion(base::UTF8ToUTF16("歌"));
  EXPECT_TRUE(ime_inline_autocomplete_view->GetVisible());

  GetLocationBarView()->Layout();

  // Make sure the IME inline autocomplete view starts at the end of
  // |omnibox_view_views|.
  EXPECT_EQ(omnibox_view_views->bounds().right(),
            ime_inline_autocomplete_view->x());
}

class SecurityIndicatorTest : public InProcessBrowserTest {
 public:
  void SetUpOnMainThread() override {
    host_resolver()->AddRule("*", "127.0.0.1");
  }

  SecurityIndicatorTest() = default;

  LocationBarView* GetLocationBarView() {
    BrowserView* browser_view =
        BrowserView::GetBrowserViewForBrowser(browser());
    return browser_view->GetLocationBarView();
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(SecurityIndicatorTest);
};

// Check that the security indicator text is not shown for HTTPS and "Not
// secure" is shown for HTTP.
IN_PROC_BROWSER_TEST_F(SecurityIndicatorTest, CheckIndicatorText) {
  net::EmbeddedTestServer secure_server(net::EmbeddedTestServer::TYPE_HTTPS);
  secure_server.SetSSLConfig(
      net::test_server::EmbeddedTestServer::CERT_TEST_NAMES);
  secure_server.AddDefaultHandlers(GetChromeTestDataDir());
  ASSERT_TRUE(secure_server.Start());
  const GURL kMockSecureURL = secure_server.GetURL("a.test", "/empty.html");

  ASSERT_TRUE(embedded_test_server()->Start());
  const GURL kMockNonsecureURL =
      embedded_test_server()->GetURL("example.test", "/empty.html");

  content::WebContents* tab =
      browser()->tab_strip_model()->GetActiveWebContents();
  ASSERT_TRUE(tab);
  SecurityStateTabHelper* helper = SecurityStateTabHelper::FromWebContents(tab);
  ASSERT_TRUE(helper);
  LocationBarView* location_bar_view = GetLocationBarView();

  ui_test_utils::NavigateToURL(browser(), kMockSecureURL);
  EXPECT_EQ(security_state::SECURE, helper->GetSecurityLevel());
  EXPECT_FALSE(location_bar_view->location_icon_view()->ShouldShowLabel());
  EXPECT_TRUE(location_bar_view->location_icon_view()->GetText().empty());

  ui_test_utils::NavigateToURL(browser(), kMockNonsecureURL);
  EXPECT_EQ(security_state::WARNING, helper->GetSecurityLevel());
  EXPECT_TRUE(location_bar_view->location_icon_view()->ShouldShowLabel());
  EXPECT_TRUE(base::LowerCaseEqualsASCII(
      location_bar_view->location_icon_view()->GetText(), "not secure"));
}
