// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/blocked_content/safe_browsing_triggered_popup_blocker.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/macros.h"
#include "base/run_loop.h"
#include "base/task/post_task.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "components/blocked_content/popup_blocker.h"
#include "components/blocked_content/popup_blocker_tab_helper.h"
#include "components/blocked_content/popup_navigation_delegate.h"
#include "components/blocked_content/test/test_popup_navigation_delegate.h"
#include "components/content_settings/browser/page_specific_content_settings.h"
#include "components/content_settings/browser/test_page_specific_content_settings_delegate.h"
#include "components/content_settings/core/browser/host_content_settings_map.h"
#include "components/subresource_filter/content/browser/fake_safe_browsing_database_manager.h"
#include "components/subresource_filter/content/browser/subresource_filter_client.h"
#include "components/subresource_filter/content/browser/subresource_filter_observer_manager.h"
#include "components/subresource_filter/content/browser/subresource_filter_safe_browsing_activation_throttle.h"
#include "components/subresource_filter/content/browser/subresource_filter_safe_browsing_client.h"
#include "components/subresource_filter/core/browser/subresource_filter_constants.h"
#include "components/sync_preferences/testing_pref_service_syncable.h"
#include "components/user_prefs/user_prefs.h"
#include "content/public/browser/browser_context.h"
#include "content/public/browser/browser_task_traits.h"
#include "content/public/browser/navigation_handle.h"
#include "content/public/browser/navigation_throttle.h"
#include "content/public/test/navigation_simulator.h"
#include "content/public/test/test_navigation_throttle_inserter.h"
#include "content/public/test/test_renderer_host.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/navigation/triggering_event_info.h"
#include "third_party/blink/public/mojom/window_features/window_features.mojom.h"
#include "ui/base/page_transition_types.h"
#include "ui/base/window_open_disposition.h"
#include "url/gurl.h"

namespace blocked_content {
const char kNumBlockedHistogram[] =
    "ContentSettings.Popups.StrongBlocker.NumBlocked";

class SafeBrowsingTriggeredPopupBlockerTest
    : public content::RenderViewHostTestHarness,
      public subresource_filter::SubresourceFilterClient {
 public:
  SafeBrowsingTriggeredPopupBlockerTest() = default;
  ~SafeBrowsingTriggeredPopupBlockerTest() override {
    settings_map_->ShutdownOnUIThread();
  }

  // subresource_filter::SubresourceFilterClient:
  void ShowNotification() override {}
  subresource_filter::mojom::ActivationLevel OnPageActivationComputed(
      content::NavigationHandle* navigation_handle,
      subresource_filter::mojom::ActivationLevel initial_activation_level,
      subresource_filter::ActivationDecision* decision) override {
    return initial_activation_level;
  }
  void OnAdsViolationTriggered(
      content::RenderFrameHost*,
      subresource_filter::mojom::AdsViolation) override {}
  const scoped_refptr<safe_browsing::SafeBrowsingDatabaseManager>
  GetSafeBrowsingDatabaseManager() override {
    return nullptr;
  }
  void OnReloadRequested() override {}

  // content::RenderViewHostTestHarness:
  void SetUp() override {
    content::RenderViewHostTestHarness::SetUp();

    fake_safe_browsing_database_ =
        base::MakeRefCounted<FakeSafeBrowsingDatabaseManager>();

    user_prefs::UserPrefs::Set(browser_context(), &pref_service_);
    SafeBrowsingTriggeredPopupBlocker::RegisterProfilePrefs(
        pref_service_.registry());
    HostContentSettingsMap::RegisterProfilePrefs(pref_service_.registry());
    settings_map_ = base::MakeRefCounted<HostContentSettingsMap>(
        &pref_service_, false /* is_off_the_record */,
        false /* store_last_modified */, false /* restore_session*/);

    scoped_feature_list_ = DefaultFeatureList();
    subresource_filter::SubresourceFilterObserverManager::CreateForWebContents(
        web_contents());
    PopupBlockerTabHelper::CreateForWebContents(web_contents());
    content_settings::PageSpecificContentSettings::CreateForWebContents(
        web_contents(),
        std::make_unique<
            content_settings::TestPageSpecificContentSettingsDelegate>(
            /*prefs=*/nullptr, settings_map_.get()));
    popup_blocker_ =
        SafeBrowsingTriggeredPopupBlocker::FromWebContents(web_contents());

    throttle_inserter_ =
        std::make_unique<content::TestNavigationThrottleInserter>(
            web_contents(),
            base::BindRepeating(
                &SafeBrowsingTriggeredPopupBlockerTest::CreateThrottle,
                base::Unretained(this)));
  }

  virtual std::unique_ptr<base::test::ScopedFeatureList> DefaultFeatureList() {
    auto feature_list = std::make_unique<base::test::ScopedFeatureList>();
    feature_list->InitAndEnableFeature(kAbusiveExperienceEnforce);
    return feature_list;
  }

  FakeSafeBrowsingDatabaseManager* fake_safe_browsing_database() {
    return fake_safe_browsing_database_.get();
  }

  base::test::ScopedFeatureList* ResetFeatureAndGet() {
    scoped_feature_list_ = std::make_unique<base::test::ScopedFeatureList>();
    return scoped_feature_list_.get();
  }

  SafeBrowsingTriggeredPopupBlocker* popup_blocker() { return popup_blocker_; }

  void SimulateDeleteContents() {
    DeleteContents();
    popup_blocker_ = nullptr;
  }

  void MarkUrlAsAbusiveWithLevel(const GURL& url,
                                 safe_browsing::SubresourceFilterLevel level) {
    safe_browsing::ThreatMetadata metadata;
    metadata.subresource_filter_match
        [safe_browsing::SubresourceFilterType::ABUSIVE] = level;
    fake_safe_browsing_database()->AddBlocklistedUrl(
        url, safe_browsing::SB_THREAT_TYPE_SUBRESOURCE_FILTER, metadata);
  }

  void MarkUrlAsAbusiveEnforce(const GURL& url) {
    MarkUrlAsAbusiveWithLevel(url,
                              safe_browsing::SubresourceFilterLevel::ENFORCE);
  }

  void MarkUrlAsAbusiveWarning(const GURL& url) {
    MarkUrlAsAbusiveWithLevel(url, safe_browsing::SubresourceFilterLevel::WARN);
  }

  const std::vector<std::string>& GetMainFrameConsoleMessages() {
    content::RenderFrameHostTester* rfh_tester =
        content::RenderFrameHostTester::For(main_rfh());
    return rfh_tester->GetConsoleMessages();
  }

  HostContentSettingsMap* settings_map() { return settings_map_.get(); }

 private:
  std::unique_ptr<content::NavigationThrottle> CreateThrottle(
      content::NavigationHandle* handle) {
    return std::make_unique<
        subresource_filter::SubresourceFilterSafeBrowsingActivationThrottle>(
        handle, this, content::GetIOThreadTaskRunner({}),
        fake_safe_browsing_database_);
  }

  std::unique_ptr<base::test::ScopedFeatureList> scoped_feature_list_;
  scoped_refptr<FakeSafeBrowsingDatabaseManager> fake_safe_browsing_database_;
  SafeBrowsingTriggeredPopupBlocker* popup_blocker_ = nullptr;
  std::unique_ptr<content::TestNavigationThrottleInserter> throttle_inserter_;
  sync_preferences::TestingPrefServiceSyncable pref_service_;
  scoped_refptr<HostContentSettingsMap> settings_map_;

  DISALLOW_COPY_AND_ASSIGN(SafeBrowsingTriggeredPopupBlockerTest);
};

struct RedirectSamplesAndResults {
  GURL initial_url;
  GURL redirect_url;
  bool expect_strong_blocker;
};

// We always make our decision to trigger on the last entry in the chain.
TEST_F(SafeBrowsingTriggeredPopupBlockerTest,
       MatchOnSafeBrowsingWithRedirectChain) {
  GURL enforce_url("https://example.enforce");
  GURL warning_url("https://example.warning");
  GURL regular_url("https://example.regular");
  MarkUrlAsAbusiveEnforce(enforce_url);
  MarkUrlAsAbusiveWarning(warning_url);

  const RedirectSamplesAndResults kTestCases[] = {
      {enforce_url, regular_url, false},
      {regular_url, enforce_url, true},
      {warning_url, enforce_url, true},
      {enforce_url, warning_url, false}};

  for (const auto& test_case : kTestCases) {
    std::unique_ptr<content::NavigationSimulator> simulator =
        content::NavigationSimulator::CreateRendererInitiated(
            test_case.initial_url, web_contents()->GetMainFrame());
    simulator->Start();
    simulator->Redirect(test_case.redirect_url);
    simulator->Commit();
    EXPECT_EQ(test_case.expect_strong_blocker,
              popup_blocker()->ShouldApplyAbusivePopupBlocker());
  }
}

TEST_F(SafeBrowsingTriggeredPopupBlockerTest, MatchingURL_BlocksPopupAndLogs) {
  const GURL url("https://example.test/");
  MarkUrlAsAbusiveEnforce(url);
  NavigateAndCommit(url);
  EXPECT_TRUE(GetMainFrameConsoleMessages().empty());

  EXPECT_TRUE(popup_blocker()->ShouldApplyAbusivePopupBlocker());
  EXPECT_EQ(1u, GetMainFrameConsoleMessages().size());
  EXPECT_EQ(GetMainFrameConsoleMessages().front(), kAbusiveEnforceMessage);
}

TEST_F(SafeBrowsingTriggeredPopupBlockerTest,
       MatchingURL_BlocksPopupFromOpenURL) {
  const GURL url("https://example.test/");
  MarkUrlAsAbusiveEnforce(url);
  NavigateAndCommit(url);

  // If the popup is coming from OpenURL params, the strong popup blocker is
  // only going to look at the triggering event info. It will only block the
  // popup if we know the triggering event is untrusted.
  GURL popup_url("https://example.popup/");
  content::OpenURLParams params(
      popup_url, content::Referrer(), WindowOpenDisposition::NEW_FOREGROUND_TAB,
      ui::PAGE_TRANSITION_LINK, true /* is_renderer_initiated */);
  params.user_gesture = true;
  params.triggering_event_info =
      blink::TriggeringEventInfo::kFromUntrustedEvent;

  MaybeBlockPopup(web_contents(), nullptr,
                  std::make_unique<TestPopupNavigationDelegate>(
                      popup_url, nullptr /* result_holder */),
                  &params, blink::mojom::WindowFeatures(), settings_map());

  EXPECT_EQ(1u, PopupBlockerTabHelper::FromWebContents(web_contents())
                    ->GetBlockedPopupsCount());
}

TEST_F(SafeBrowsingTriggeredPopupBlockerTest,
       MatchingURLTrusted_DoesNotBlockPopup) {
  const GURL url("https://example.test/");
  MarkUrlAsAbusiveEnforce(url);
  NavigateAndCommit(url);

  // If the popup is coming from OpenURL params, the strong popup blocker is
  // only going to look at the triggering event info. It will only block the
  // popup if we know the triggering event is untrusted.
  GURL popup_url("https://example.popup/");
  content::OpenURLParams params(
      popup_url, content::Referrer(), WindowOpenDisposition::NEW_FOREGROUND_TAB,
      ui::PAGE_TRANSITION_LINK, true /* is_renderer_initiated */);
  params.user_gesture = true;
  params.triggering_event_info = blink::TriggeringEventInfo::kFromTrustedEvent;

  MaybeBlockPopup(web_contents(), nullptr,
                  std::make_unique<TestPopupNavigationDelegate>(
                      popup_url, nullptr /* result_holder */),
                  &params, blink::mojom::WindowFeatures(), settings_map());

  EXPECT_EQ(0u, PopupBlockerTabHelper::FromWebContents(web_contents())
                    ->GetBlockedPopupsCount());
}

TEST_F(SafeBrowsingTriggeredPopupBlockerTest, NoMatch_NoBlocking) {
  const GURL url("https://example.test/");
  NavigateAndCommit(url);
  EXPECT_FALSE(popup_blocker()->ShouldApplyAbusivePopupBlocker());
  EXPECT_TRUE(GetMainFrameConsoleMessages().empty());
}

TEST_F(SafeBrowsingTriggeredPopupBlockerTest, FeatureEnabledByDefault) {
  ResetFeatureAndGet();
  SafeBrowsingTriggeredPopupBlocker::MaybeCreate(web_contents());
  EXPECT_NE(nullptr,
            SafeBrowsingTriggeredPopupBlocker::FromWebContents(web_contents()));
}

TEST_F(SafeBrowsingTriggeredPopupBlockerTest, OnlyBlockOnMatchingUrls) {
  const GURL url1("https://example.first/");
  const GURL url2("https://example.second/");
  const GURL url3("https://example.third/");
  // Only mark url2 as abusive.
  MarkUrlAsAbusiveEnforce(url2);

  NavigateAndCommit(url1);
  EXPECT_FALSE(popup_blocker()->ShouldApplyAbusivePopupBlocker());

  NavigateAndCommit(url2);
  EXPECT_TRUE(popup_blocker()->ShouldApplyAbusivePopupBlocker());

  NavigateAndCommit(url3);
  EXPECT_FALSE(popup_blocker()->ShouldApplyAbusivePopupBlocker());

  NavigateAndCommit(url1);
  EXPECT_FALSE(popup_blocker()->ShouldApplyAbusivePopupBlocker());
}

TEST_F(SafeBrowsingTriggeredPopupBlockerTest,
       SameDocumentNavigation_MaintainsBlocking) {
  const GURL url("https://example.first/");
  const GURL hash_url("https://example.first/#hash");

  MarkUrlAsAbusiveEnforce(url);
  NavigateAndCommit(url);
  EXPECT_TRUE(popup_blocker()->ShouldApplyAbusivePopupBlocker());

  // This is merely a same document navigation, keep the popup blocker.
  NavigateAndCommit(hash_url);
  EXPECT_TRUE(popup_blocker()->ShouldApplyAbusivePopupBlocker());
}

TEST_F(SafeBrowsingTriggeredPopupBlockerTest,
       FailNavigation_MaintainsBlocking) {
  const GURL url("https://example.first/");
  const GURL fail_url("https://example.fail/");

  MarkUrlAsAbusiveEnforce(url);
  NavigateAndCommit(url);
  EXPECT_TRUE(popup_blocker()->ShouldApplyAbusivePopupBlocker());

  // Abort the navigation before it commits.
  content::NavigationSimulator::NavigateAndFailFromDocument(
      fail_url, net::ERR_ABORTED, main_rfh());
  EXPECT_TRUE(popup_blocker()->ShouldApplyAbusivePopupBlocker());

  // Committing an error page should probably reset the blocker though, despite
  // the fact that it is probably a bug for an error page to spawn popups.
  content::NavigationSimulator::NavigateAndFailFromDocument(
      fail_url, net::ERR_CONNECTION_RESET, main_rfh());
  EXPECT_FALSE(popup_blocker()->ShouldApplyAbusivePopupBlocker());
}

TEST_F(SafeBrowsingTriggeredPopupBlockerTest, LogActions) {
  base::HistogramTester histogram_tester;
  const char kActionHistogram[] = "ContentSettings.Popups.StrongBlockerActions";
  int total_count = 0;
  // Call this when a new histogram entry is logged. Call it multiple times if
  // multiple entries are logged.
  auto check_histogram = [&](SafeBrowsingTriggeredPopupBlocker::Action action,
                             int expected_count) {
    histogram_tester.ExpectBucketCount(
        kActionHistogram, static_cast<int>(action), expected_count);
    total_count++;
  };

  const GURL url_enforce("https://example.enforce/");
  const GURL url_warn("https://example.warn/");
  const GURL url_nothing("https://example.nothing/");
  MarkUrlAsAbusiveEnforce(url_enforce);
  MarkUrlAsAbusiveWarning(url_warn);

  // Navigate to an enforce site.
  NavigateAndCommit(url_enforce);
  check_histogram(SafeBrowsingTriggeredPopupBlocker::Action::kNavigation, 1);
  check_histogram(SafeBrowsingTriggeredPopupBlocker::Action::kEnforcedSite, 1);
  histogram_tester.ExpectTotalCount(kActionHistogram, total_count);

  // Block two popups.
  EXPECT_TRUE(popup_blocker()->ShouldApplyAbusivePopupBlocker());
  check_histogram(SafeBrowsingTriggeredPopupBlocker::Action::kConsidered, 1);
  check_histogram(SafeBrowsingTriggeredPopupBlocker::Action::kBlocked, 1);
  histogram_tester.ExpectTotalCount(kActionHistogram, total_count);

  EXPECT_TRUE(popup_blocker()->ShouldApplyAbusivePopupBlocker());
  check_histogram(SafeBrowsingTriggeredPopupBlocker::Action::kConsidered, 2);
  check_histogram(SafeBrowsingTriggeredPopupBlocker::Action::kBlocked, 2);
  histogram_tester.ExpectTotalCount(kActionHistogram, total_count);

  // Only log the num blocked histogram after navigation.
  histogram_tester.ExpectTotalCount(kNumBlockedHistogram, 0);

  // Navigate to a warn site.
  NavigateAndCommit(url_warn);
  histogram_tester.ExpectBucketCount(kNumBlockedHistogram, 2, 1);

  check_histogram(SafeBrowsingTriggeredPopupBlocker::Action::kNavigation, 2);
  check_histogram(SafeBrowsingTriggeredPopupBlocker::Action::kWarningSite, 1);
  histogram_tester.ExpectTotalCount(kActionHistogram, total_count);

  // Let one popup through.
  EXPECT_FALSE(popup_blocker()->ShouldApplyAbusivePopupBlocker());
  check_histogram(SafeBrowsingTriggeredPopupBlocker::Action::kConsidered, 3);
  histogram_tester.ExpectTotalCount(kActionHistogram, total_count);

  // Navigate to a site not matched in Safe Browsing.
  NavigateAndCommit(url_nothing);
  check_histogram(SafeBrowsingTriggeredPopupBlocker::Action::kNavigation, 3);
  histogram_tester.ExpectTotalCount(kActionHistogram, total_count);

  // Let one popup through.
  EXPECT_FALSE(popup_blocker()->ShouldApplyAbusivePopupBlocker());
  check_histogram(SafeBrowsingTriggeredPopupBlocker::Action::kConsidered, 4);
  histogram_tester.ExpectTotalCount(kActionHistogram, total_count);

  histogram_tester.ExpectTotalCount(kNumBlockedHistogram, 1);
}

TEST_F(SafeBrowsingTriggeredPopupBlockerTest, LogBlockMetricsOnClose) {
  base::HistogramTester histogram_tester;
  const GURL url_enforce("https://example.enforce/");
  MarkUrlAsAbusiveEnforce(url_enforce);

  NavigateAndCommit(url_enforce);
  EXPECT_TRUE(popup_blocker()->ShouldApplyAbusivePopupBlocker());

  histogram_tester.ExpectTotalCount(kNumBlockedHistogram, 0);
  // Simulate deleting the web contents.
  SimulateDeleteContents();
  histogram_tester.ExpectUniqueSample(kNumBlockedHistogram, 1, 1);
}

TEST_F(SafeBrowsingTriggeredPopupBlockerTest,
       WarningMatchWithoutAdBlockOnAbusiveSites_OnlyLogs) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndDisableFeature(
      subresource_filter::kFilterAdsOnAbusiveSites);

  const GURL url("https://example.test/");
  MarkUrlAsAbusiveWarning(url);
  NavigateAndCommit(url);

  // Warning should come at navigation commit time, not at popup time.
  EXPECT_EQ(1u, GetMainFrameConsoleMessages().size());
  EXPECT_EQ(GetMainFrameConsoleMessages().front(), kAbusiveWarnMessage);

  EXPECT_FALSE(popup_blocker()->ShouldApplyAbusivePopupBlocker());
}

TEST_F(SafeBrowsingTriggeredPopupBlockerTest,
       WarningMatchWithAdBlockOnAbusiveSites_OnlyLogs) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeature(
      subresource_filter::kFilterAdsOnAbusiveSites);

  const GURL url("https://example.test/");
  MarkUrlAsAbusiveWarning(url);
  NavigateAndCommit(url);

  // Warning should come at navigation commit time, not at popup time.
  EXPECT_EQ(2u, GetMainFrameConsoleMessages().size());
  EXPECT_EQ(GetMainFrameConsoleMessages().front(), kAbusiveWarnMessage);
  EXPECT_EQ(GetMainFrameConsoleMessages().back(),
            subresource_filter::kActivationWarningConsoleMessage);

  EXPECT_FALSE(popup_blocker()->ShouldApplyAbusivePopupBlocker());
}

TEST_F(SafeBrowsingTriggeredPopupBlockerTest, EnforcementRedirectPosition) {
  // Turn on the feature to perform safebrowsing on redirects.
  base::test::ScopedFeatureList scoped_feature_list;

  const GURL enforce_url("https://enforce.test/");
  const GURL warn_url("https://warn.test/");
  MarkUrlAsAbusiveEnforce(enforce_url);
  MarkUrlAsAbusiveWarning(warn_url);

  using subresource_filter::RedirectPosition;
  struct {
    std::vector<const char*> urls;
    base::Optional<RedirectPosition> last_enforcement_position;
  } kTestCases[] = {
      {{"https://normal.test/"}, base::nullopt},
      {{"https://enforce.test/"}, RedirectPosition::kOnly},
      {{"https://warn.test/"}, base::nullopt},

      {{"https://normal.test/", "https://warn.test/"}, base::nullopt},
      {{"https://normal.test/", "https://normal.test/",
        "https://enforce.test/"},
       RedirectPosition::kLast},

      {{"https://enforce.test", "https://normal.test/", "https://warn.test/"},
       RedirectPosition::kFirst},
      {{"https://warn.test/", "https://normal.test/"}, base::nullopt},

      {{"https://normal.test/", "https://enforce.test/",
        "https://normal.test/"},
       RedirectPosition::kMiddle},
  };

  for (const auto& test_case : kTestCases) {
    base::HistogramTester histograms;
    const GURL& first_url = GURL(test_case.urls.front());
    auto navigation_simulator =
        content::NavigationSimulator::CreateRendererInitiated(first_url,
                                                              main_rfh());
    for (size_t i = 1; i < test_case.urls.size(); ++i) {
      navigation_simulator->Redirect(GURL(test_case.urls[i]));
    }
    navigation_simulator->Commit();

    histograms.ExpectTotalCount(
        "SubresourceFilter.PageLoad.Activation.RedirectPosition2.Enforcement",
        test_case.last_enforcement_position.has_value() ? 1 : 0);
    if (test_case.last_enforcement_position.has_value()) {
      histograms.ExpectUniqueSample(
          "SubresourceFilter.PageLoad.Activation.RedirectPosition2.Enforcement",
          static_cast<int>(test_case.last_enforcement_position.value()), 1);
    }
  }
}
}  // namespace blocked_content
