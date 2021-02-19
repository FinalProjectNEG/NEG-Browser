// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/hash/hash.h"
#include "base/memory/ref_counted_memory.h"
#include "base/path_service.h"
#include "base/strings/strcat.h"
#include "base/strings/string_number_conversions.h"
#include "base/threading/thread_restrictions.h"
#include "build/build_config.h"
#include "content/browser/child_process_security_policy_impl.h"
#include "content/browser/renderer_host/frame_tree_node.h"
#include "content/browser/web_contents/web_contents_impl.h"
#include "content/browser/webui/web_ui_controller_factory_registry.h"
#include "content/common/content_navigation_policy.h"
#include "content/public/browser/site_isolation_policy.h"
#include "content/public/browser/url_data_source.h"
#include "content/public/browser/web_ui.h"
#include "content/public/browser/web_ui_controller.h"
#include "content/public/browser/web_ui_data_source.h"
#include "content/public/common/bindings_policy.h"
#include "content/public/common/content_paths.h"
#include "content/public/common/url_constants.h"
#include "content/public/test/browser_test.h"
#include "content/public/test/browser_test_utils.h"
#include "content/public/test/content_browser_test.h"
#include "content/public/test/content_browser_test_utils.h"
#include "content/public/test/test_frame_navigation_observer.h"
#include "content/public/test/test_navigation_observer.h"
#include "content/public/test/test_utils.h"
#include "content/public/test/web_ui_browsertest_util.h"
#include "content/shell/browser/shell.h"
#include "content/test/content_browser_test_utils_internal.h"
#include "net/base/url_util.h"
#include "url/gurl.h"

namespace content {

namespace {

// Loads a given module script. The promise resolves to true if the script loads
// successfully, and false otherwise.
const char kAddScriptModuleScript[] =
    "new Promise((resolve, reject) => {\n"
    "  const script = document.createElement('script');\n"
    "  script.src = $1;\n"
    "  script.type = 'module';\n"
    "  script.onload = () => resolve(true);\n"
    "  script.onerror = () => resolve(false);\n"
    "  document.body.appendChild(script);\n"
    "});\n";

// Path to an existing chrome-untrusted://resources script.
const char kSharedResourcesModuleJsPath[] = "resources/js/assert.m.js";

}  // namespace

class WebUISecurityTest : public ContentBrowserTest {
 public:
  WebUISecurityTest() { WebUIControllerFactory::RegisterFactory(&factory_); }

  ~WebUISecurityTest() override {
    WebUIControllerFactory::UnregisterFactoryForTesting(&factory_);
  }

  TestWebUIControllerFactory* factory() { return &factory_; }

 private:
  TestWebUIControllerFactory factory_;

  DISALLOW_COPY_AND_ASSIGN(WebUISecurityTest);
};

// Verify chrome-untrusted:// have no bindings.
IN_PROC_BROWSER_TEST_F(WebUISecurityTest, UntrustedNoBindings) {
  auto* web_contents = shell()->web_contents();
  AddUntrustedDataSource(web_contents->GetBrowserContext(), "test-host");

  const GURL untrusted_url(GetChromeUntrustedUIURL("test-host/title1.html"));
  EXPECT_TRUE(NavigateToURL(web_contents, untrusted_url));

  EXPECT_FALSE(ChildProcessSecurityPolicyImpl::GetInstance()->HasWebUIBindings(
      shell()->web_contents()->GetMainFrame()->GetProcess()->GetID()));
  EXPECT_EQ(0, shell()->web_contents()->GetMainFrame()->GetEnabledBindings());
}

// Loads a WebUI which does not have any bindings.
IN_PROC_BROWSER_TEST_F(WebUISecurityTest, NoBindings) {
  GURL test_url(GetWebUIURL("web-ui/title1.html?bindings=0"));
  EXPECT_TRUE(NavigateToURL(shell(), test_url));

  EXPECT_FALSE(ChildProcessSecurityPolicyImpl::GetInstance()->HasWebUIBindings(
      shell()->web_contents()->GetMainFrame()->GetProcess()->GetID()));
  EXPECT_EQ(0, shell()->web_contents()->GetMainFrame()->GetEnabledBindings());
}

// Loads a WebUI which has WebUI bindings.
IN_PROC_BROWSER_TEST_F(WebUISecurityTest, WebUIBindings) {
  GURL test_url(GetWebUIURL("web-ui/title1.html?bindings=" +
                            base::NumberToString(BINDINGS_POLICY_WEB_UI)));
  EXPECT_TRUE(NavigateToURL(shell(), test_url));

  EXPECT_TRUE(ChildProcessSecurityPolicyImpl::GetInstance()->HasWebUIBindings(
      shell()->web_contents()->GetMainFrame()->GetProcess()->GetID()));
  EXPECT_EQ(BINDINGS_POLICY_WEB_UI,
            shell()->web_contents()->GetMainFrame()->GetEnabledBindings());
}

// Loads a WebUI which has Mojo bindings.
IN_PROC_BROWSER_TEST_F(WebUISecurityTest, MojoBindings) {
  GURL test_url(GetWebUIURL("web-ui/title1.html?bindings=" +
                            base::NumberToString(BINDINGS_POLICY_MOJO_WEB_UI)));
  EXPECT_TRUE(NavigateToURL(shell(), test_url));

  EXPECT_TRUE(ChildProcessSecurityPolicyImpl::GetInstance()->HasWebUIBindings(
      shell()->web_contents()->GetMainFrame()->GetProcess()->GetID()));
  EXPECT_EQ(BINDINGS_POLICY_MOJO_WEB_UI,
            shell()->web_contents()->GetMainFrame()->GetEnabledBindings());
}

// Loads a WebUI which has both WebUI and Mojo bindings.
IN_PROC_BROWSER_TEST_F(WebUISecurityTest, WebUIAndMojoBindings) {
  GURL test_url(GetWebUIURL("web-ui/title1.html?bindings=" +
                            base::NumberToString(BINDINGS_POLICY_WEB_UI |
                                                 BINDINGS_POLICY_MOJO_WEB_UI)));
  EXPECT_TRUE(NavigateToURL(shell(), test_url));

  EXPECT_TRUE(ChildProcessSecurityPolicyImpl::GetInstance()->HasWebUIBindings(
      shell()->web_contents()->GetMainFrame()->GetProcess()->GetID()));
  EXPECT_EQ(BINDINGS_POLICY_WEB_UI | BINDINGS_POLICY_MOJO_WEB_UI,
            shell()->web_contents()->GetMainFrame()->GetEnabledBindings());
}

// Verify that reloading a WebUI document or navigating between documents on
// the same WebUI will result in using the same SiteInstance and will not
// create a new WebUI instance.
IN_PROC_BROWSER_TEST_F(WebUISecurityTest, WebUIReuse) {
  GURL test_url(GetWebUIURL("web-ui/title1.html"));
  EXPECT_TRUE(NavigateToURL(shell(), test_url));

  FrameTreeNode* root = static_cast<WebContentsImpl*>(shell()->web_contents())
                            ->GetFrameTree()
                            ->root();

  // Capture the SiteInstance and WebUI used in the first navigation to compare
  // with the ones used after the reload.
  scoped_refptr<SiteInstance> initial_site_instance =
      root->current_frame_host()->GetSiteInstance();
  WebUI* initial_web_ui = root->current_frame_host()->web_ui();

  // Reload the document and check that SiteInstance and WebUI are reused.
  TestFrameNavigationObserver observer(root);
  shell()->web_contents()->GetController().Reload(ReloadType::NORMAL, false);
  observer.Wait();
  EXPECT_TRUE(observer.last_navigation_succeeded());
  EXPECT_EQ(test_url, observer.last_committed_url());

  EXPECT_EQ(initial_site_instance,
            root->current_frame_host()->GetSiteInstance());
  EXPECT_EQ(initial_web_ui, root->current_frame_host()->web_ui());

  // Navigate to another document on the same WebUI and check that SiteInstance
  // and WebUI are reused.
  GURL next_url(GetWebUIURL("web-ui/title2.html"));
  EXPECT_TRUE(NavigateToURL(shell(), next_url));

  EXPECT_EQ(initial_site_instance,
            root->current_frame_host()->GetSiteInstance());
  EXPECT_EQ(initial_web_ui, root->current_frame_host()->web_ui());
}

// Verify that a WebUI can add a subframe for its own WebUI.
IN_PROC_BROWSER_TEST_F(WebUISecurityTest, WebUISameSiteSubframe) {
  GURL test_url(GetWebUIURL("web-ui/page_with_blank_iframe.html"));
  EXPECT_TRUE(NavigateToURL(shell(), test_url));

  FrameTreeNode* root = static_cast<WebContentsImpl*>(shell()->web_contents())
                            ->GetFrameTree()
                            ->root();
  EXPECT_EQ(1U, root->child_count());

  TestFrameNavigationObserver observer(root->child_at(0));
  GURL subframe_url(GetWebUIURL("web-ui/title1.html?noxfo=true"));
  NavigateFrameToURL(root->child_at(0), subframe_url);

  EXPECT_TRUE(observer.last_navigation_succeeded());
  EXPECT_EQ(subframe_url, observer.last_committed_url());
  EXPECT_EQ(root->current_frame_host()->GetSiteInstance(),
            root->child_at(0)->current_frame_host()->GetSiteInstance());
  EXPECT_EQ(
      GetWebUIURL("web-ui"),
      root->child_at(0)->current_frame_host()->GetSiteInstance()->GetSiteURL());

  // The subframe should have its own WebUI object different from the parent
  // frame.
  EXPECT_NE(nullptr, root->child_at(0)->current_frame_host()->web_ui());
  EXPECT_NE(root->current_frame_host()->web_ui(),
            root->child_at(0)->current_frame_host()->web_ui());
}

// Verify that a WebUI can add a subframe to another WebUI and they will be
// correctly isolated in separate SiteInstances and processes. The subframe
// also uses WebUI with bindings different than the parent to ensure this is
// successfully handled.
IN_PROC_BROWSER_TEST_F(WebUISecurityTest, WebUICrossSiteSubframe) {
  GURL main_frame_url(GetWebUIURL("web-ui/page_with_blank_iframe.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_frame_url));

  FrameTreeNode* root = static_cast<WebContentsImpl*>(shell()->web_contents())
                            ->GetFrameTree()
                            ->root();
  EXPECT_EQ(1U, root->child_count());
  FrameTreeNode* child = root->child_at(0);

  EXPECT_EQ(BINDINGS_POLICY_WEB_UI,
            root->current_frame_host()->GetEnabledBindings());
  EXPECT_EQ(shell()->web_contents()->GetSiteInstance(),
            child->current_frame_host()->GetSiteInstance());

  // Navigate the subframe using renderer-initiated navigation.
  {
    TestFrameNavigationObserver observer(child);
    GURL child_frame_url(
        GetWebUIURL("web-ui-subframe/title2.html?noxfo=true&bindings=" +
                    base::NumberToString(BINDINGS_POLICY_MOJO_WEB_UI)));
    EXPECT_TRUE(ExecJs(shell(),
                       JsReplace("document.getElementById($1).src = $2;",
                                 "test_iframe", child_frame_url),
                       EXECUTE_SCRIPT_DEFAULT_OPTIONS, 1 /* world_id */));
    observer.Wait();
    EXPECT_TRUE(observer.last_navigation_succeeded());
    EXPECT_EQ(child_frame_url, observer.last_committed_url());
    EXPECT_EQ(BINDINGS_POLICY_MOJO_WEB_UI,
              child->current_frame_host()->GetEnabledBindings());
    EXPECT_EQ(url::Origin::Create(child_frame_url),
              child->current_frame_host()->GetLastCommittedOrigin());
  }
  EXPECT_EQ(GetWebUIURL("web-ui-subframe"),
            child->current_frame_host()->GetSiteInstance()->GetSiteURL());
  EXPECT_NE(root->current_frame_host()->GetSiteInstance(),
            child->current_frame_host()->GetSiteInstance());
  EXPECT_NE(root->current_frame_host()->GetProcess(),
            child->current_frame_host()->GetProcess());
  EXPECT_NE(root->current_frame_host()->web_ui(),
            child->current_frame_host()->web_ui());
  EXPECT_NE(root->current_frame_host()->GetEnabledBindings(),
            child->current_frame_host()->GetEnabledBindings());

  // Navigate once more using renderer-initiated navigation.
  {
    TestFrameNavigationObserver observer(child);
    GURL child_frame_url(
        GetWebUIURL("web-ui-subframe/title3.html?noxfo=true&bindings=" +
                    base::NumberToString(BINDINGS_POLICY_MOJO_WEB_UI)));
    EXPECT_TRUE(ExecJs(shell(),
                       JsReplace("document.getElementById($1).src = $2;",
                                 "test_iframe", child_frame_url),
                       EXECUTE_SCRIPT_DEFAULT_OPTIONS, 1 /* world_id */));
    observer.Wait();
    EXPECT_TRUE(observer.last_navigation_succeeded());
    EXPECT_EQ(child_frame_url, observer.last_committed_url());
    EXPECT_EQ(BINDINGS_POLICY_MOJO_WEB_UI,
              child->current_frame_host()->GetEnabledBindings());
    EXPECT_EQ(url::Origin::Create(child_frame_url),
              child->current_frame_host()->GetLastCommittedOrigin());
  }

  // Navigate the subframe using browser-initiated navigation.
  {
    TestFrameNavigationObserver observer(child);
    GURL child_frame_url(
        GetWebUIURL("web-ui-subframe/title1.html?noxfo=true&bindings=" +
                    base::NumberToString(BINDINGS_POLICY_MOJO_WEB_UI)));
    NavigateFrameToURL(child, child_frame_url);
    observer.Wait();
    EXPECT_TRUE(observer.last_navigation_succeeded());
    EXPECT_EQ(child_frame_url, observer.last_committed_url());
    EXPECT_EQ(BINDINGS_POLICY_MOJO_WEB_UI,
              child->current_frame_host()->GetEnabledBindings());
  }
}

// Verify that SiteInstance and WebUI reuse happens in subframes as well.
IN_PROC_BROWSER_TEST_F(WebUISecurityTest, WebUIReuseInSubframe) {
  // Disable X-Frame-Options on all WebUIs in this test, since subframe WebUI
  // reuse is expected. If the initial creation does not disable XFO, then
  // subsequent navigations will fail.
  factory()->set_disable_xfo(true);

  GURL main_frame_url(GetWebUIURL("web-ui/page_with_iframe.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_frame_url));

  FrameTreeNode* root = static_cast<WebContentsImpl*>(shell()->web_contents())
                            ->GetFrameTree()
                            ->root();
  EXPECT_EQ(1U, root->child_count());
  FrameTreeNode* child = root->child_at(0);

  // Capture the SiteInstance and WebUI used in the first navigation to compare
  // with the ones used after the reload.
  scoped_refptr<SiteInstance> initial_site_instance =
      child->current_frame_host()->GetSiteInstance();
  WebUI* initial_web_ui = child->current_frame_host()->web_ui();
  GlobalFrameRoutingId initial_rfh_id =
      child->current_frame_host()->GetGlobalFrameRoutingId();

  GURL subframe_same_site_url(GetWebUIURL("web-ui/title2.html"));
  {
    TestFrameNavigationObserver observer(child);
    NavigateFrameToURL(child, subframe_same_site_url);
    observer.Wait();
    EXPECT_TRUE(observer.last_navigation_succeeded());
    EXPECT_EQ(subframe_same_site_url, observer.last_committed_url());
  }
  EXPECT_EQ(initial_site_instance,
            child->current_frame_host()->GetSiteInstance());
  if (ShouldCreateNewHostForSameSiteSubframe()) {
    EXPECT_NE(initial_web_ui, child->current_frame_host()->web_ui());
  } else {
    EXPECT_EQ(initial_web_ui, child->current_frame_host()->web_ui());
  }

  // Navigate the child frame cross-site.
  GURL subframe_cross_site_url(GetWebUIURL("web-ui-subframe/title1.html"));
  {
    TestFrameNavigationObserver observer(child);
    NavigateFrameToURL(child, subframe_cross_site_url);
    observer.Wait();
    EXPECT_TRUE(observer.last_navigation_succeeded());
    EXPECT_EQ(subframe_cross_site_url, observer.last_committed_url());
  }
  EXPECT_NE(root->current_frame_host()->GetSiteInstance(),
            child->current_frame_host()->GetSiteInstance());
  EXPECT_NE(root->current_frame_host()->web_ui(),
            child->current_frame_host()->web_ui());
  EXPECT_NE(initial_web_ui, child->current_frame_host()->web_ui());

  // Capture the new SiteInstance and WebUI of the subframe and navigate it to
  // another document on the same site.
  scoped_refptr<SiteInstance> second_site_instance =
      child->current_frame_host()->GetSiteInstance();
  WebUI* second_web_ui = child->current_frame_host()->web_ui();

  GURL subframe_cross_site_url2(GetWebUIURL("web-ui-subframe/title2.html"));
  {
    TestFrameNavigationObserver observer(child);
    NavigateFrameToURL(child, subframe_cross_site_url2);
    observer.Wait();
    EXPECT_TRUE(observer.last_navigation_succeeded());
    EXPECT_EQ(subframe_cross_site_url2, observer.last_committed_url());
  }
  EXPECT_EQ(second_site_instance,
            child->current_frame_host()->GetSiteInstance());
  if (ShouldCreateNewHostForSameSiteSubframe()) {
    EXPECT_NE(second_web_ui, child->current_frame_host()->web_ui());
  } else {
    EXPECT_EQ(second_web_ui, child->current_frame_host()->web_ui());
  }

  // Navigate back to the first document in the subframe, which should bring
  // it back to the initial SiteInstance, but use a different RenderFrameHost
  // and by that a different WebUI instance.
  {
    TestFrameNavigationObserver observer(child);
    shell()->web_contents()->GetController().GoToOffset(-2);
    observer.Wait();
    EXPECT_TRUE(observer.last_navigation_succeeded());
    EXPECT_EQ(subframe_same_site_url, observer.last_committed_url());
  }
  EXPECT_EQ(initial_site_instance,
            child->current_frame_host()->GetSiteInstance());
  // Use routing id comparison for the RenderFrameHost as the memory allocator
  // sometime places the newly created RenderFrameHost for the back navigation
  // at the same memory location as the initial one. For this reason too, it
  // is not possible to check the web_ui() for inequality, since in some runs
  // the memory in which two different WebUI instances of the same type are
  // placed is the same.
  EXPECT_NE(initial_rfh_id,
            child->current_frame_host()->GetGlobalFrameRoutingId());
}

// Verify that if one WebUI does a window.open() to another WebUI, then the two
// are not sharing a BrowsingInstance, are isolated from each other, and both
// processes have bindings granted to them.
IN_PROC_BROWSER_TEST_F(WebUISecurityTest, WindowOpenWebUI) {
  GURL test_url(GetWebUIURL("web-ui/title1.html"));
  EXPECT_TRUE(NavigateToURL(shell(), test_url));
  EXPECT_EQ(test_url, shell()->web_contents()->GetLastCommittedURL());
  EXPECT_TRUE(shell()->web_contents()->GetMainFrame()->GetEnabledBindings() &
              BINDINGS_POLICY_WEB_UI);

  TestNavigationObserver new_contents_observer(nullptr, 1);
  new_contents_observer.StartWatchingNewWebContents();
  // Execute the script in isolated world since the default CSP disables eval
  // which ExecJs depends on.
  GURL new_tab_url(GetWebUIURL("another-web-ui/title2.html"));
  EXPECT_TRUE(ExecJs(shell(), JsReplace("window.open($1);", new_tab_url),
                     EXECUTE_SCRIPT_DEFAULT_OPTIONS, 1 /* world_id */));
  new_contents_observer.Wait();
  EXPECT_TRUE(new_contents_observer.last_navigation_succeeded());

  ASSERT_EQ(2u, Shell::windows().size());
  Shell* new_shell = Shell::windows()[1];

  EXPECT_EQ(new_tab_url, new_shell->web_contents()->GetLastCommittedURL());
  EXPECT_TRUE(new_shell->web_contents()->GetMainFrame()->GetEnabledBindings() &
              BINDINGS_POLICY_WEB_UI);

  // SiteInstances should be different and unrelated due to the
  // BrowsingInstance swaps on navigation.
  EXPECT_NE(new_shell->web_contents()->GetMainFrame()->GetSiteInstance(),
            shell()->web_contents()->GetMainFrame()->GetSiteInstance());
  EXPECT_FALSE(
      new_shell->web_contents()
          ->GetMainFrame()
          ->GetSiteInstance()
          ->IsRelatedSiteInstance(
              shell()->web_contents()->GetMainFrame()->GetSiteInstance()));

  EXPECT_NE(shell()->web_contents()->GetWebUI(),
            new_shell->web_contents()->GetWebUI());
}

// Test to verify correctness of WebUI and process model in the following
// sequence of navigations:
// * successful navigation to WebUI
// * failed navigation to WebUI
// * failed navigation to http URL
IN_PROC_BROWSER_TEST_F(WebUISecurityTest, WebUIFailedNavigation) {
  GURL start_url(GetWebUIURL("web-ui/title1.html"));
  EXPECT_TRUE(NavigateToURL(shell(), start_url));
  EXPECT_EQ(start_url, shell()->web_contents()->GetLastCommittedURL());
  EXPECT_EQ(BINDINGS_POLICY_WEB_UI,
            shell()->web_contents()->GetMainFrame()->GetEnabledBindings());

  FrameTreeNode* root = static_cast<WebContentsImpl*>(shell()->web_contents())
                            ->GetFrameTree()
                            ->root();

  GURL webui_error_url(GetWebUIURL("web-ui/error"));
  EXPECT_FALSE(NavigateToURL(shell(), webui_error_url));
  EXPECT_FALSE(root->current_frame_host()->web_ui());
  EXPECT_EQ(0, root->current_frame_host()->GetEnabledBindings());

  if (SiteIsolationPolicy::IsErrorPageIsolationEnabled(true)) {
    EXPECT_EQ(root->current_frame_host()->GetSiteInstance()->GetSiteURL(),
              GURL(kUnreachableWebDataURL));
  }

  ASSERT_TRUE(embedded_test_server()->Start());
  GURL http_error_url(
      embedded_test_server()->GetURL("foo.com", "/nonexistent"));
  EXPECT_FALSE(NavigateToURL(shell(), http_error_url));
  EXPECT_FALSE(root->current_frame_host()->web_ui());
  EXPECT_EQ(0, root->current_frame_host()->GetEnabledBindings());
}

// Verify load script from chrome-untrusted:// is blocked.
IN_PROC_BROWSER_TEST_F(WebUISecurityTest,
                       DisallowResourceRequestToChromeUntrusted) {
  ASSERT_TRUE(embedded_test_server()->Start());
  GURL web_url(embedded_test_server()->GetURL("/title2.html"));
  AddUntrustedDataSource(shell()->web_contents()->GetBrowserContext(),
                         "test-host");

  EXPECT_TRUE(NavigateToURL(shell(), web_url));
  EXPECT_EQ(web_url, shell()->web_contents()->GetLastCommittedURL());

  const char kLoadResourceScript[] =
      "new Promise((resolve) => {"
      "  const script = document.createElement('script');"
      "  script.onload = () => {"
      "    resolve('Script load should have failed');"
      "  };"
      "  script.onerror = () => {"
      "    resolve('Load failed');"
      "  };"
      "  script.src = $1;"
      "  document.body.appendChild(script);"
      "});";

  // There are no error messages in the console which is why we cannot check for
  // them.
  {
    GURL untrusted_url(GetChromeUntrustedUIURL("test-host/script.js"));
    EXPECT_EQ("Load failed",
              EvalJs(shell(), JsReplace(kLoadResourceScript, untrusted_url),
                     EXECUTE_SCRIPT_DEFAULT_OPTIONS, 1 /* world_id */));
  }
}

#if defined(OS_ANDROID)
// TODO(https://crbug.com/1085196): This sometimes fails on Android bots.
#define MAYBE_ChromeUntrustedFramesCanUseChromeUntrustedResources \
  DISABLED_ChromeUntrustedFramesCanUseChromeUntrustedResources
#else
#define MAYBE_ChromeUntrustedFramesCanUseChromeUntrustedResources \
  ChromeUntrustedFramesCanUseChromeUntrustedResources
#endif  // defined(OS_ANDROID)
IN_PROC_BROWSER_TEST_F(
    WebUISecurityTest,
    MAYBE_ChromeUntrustedFramesCanUseChromeUntrustedResources) {
  // Add a DataSource whose CSP allows chrome-untrusted://resources scripts.
  TestUntrustedDataSourceCSP csp;
  csp.script_src = "script-src chrome-untrusted://resources;";
  csp.no_trusted_types = true;
  AddUntrustedDataSource(shell()->web_contents()->GetBrowserContext(),
                         "test-host", csp);
  GURL main_frame_url(GetChromeUntrustedUIURL("test-host/title1.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_frame_url));

  // A chrome-untrusted://resources resources should load successfully.
  GURL script_url = GetChromeUntrustedUIURL(kSharedResourcesModuleJsPath);
  EXPECT_TRUE(EvalJs(shell(), JsReplace(kAddScriptModuleScript, script_url),
                     EXECUTE_SCRIPT_DEFAULT_OPTIONS, 1 /* world_id */)
                  .ExtractBool());
}

// Verify that websites cannot access chrome-untrusted://resources scripts.
IN_PROC_BROWSER_TEST_F(WebUISecurityTest,
                       DisallowChromeUntrustedResourcesFromWebFrame) {
  ASSERT_TRUE(embedded_test_server()->Start());
  GURL main_frame_url(embedded_test_server()->GetURL("/title1.html"));
  EXPECT_TRUE(NavigateToURL(shell(), main_frame_url));

  // A chrome-untrusted://resources resources should fail to load.
  GURL script_url = GetChromeUntrustedUIURL(kSharedResourcesModuleJsPath);
  EXPECT_FALSE(EvalJs(shell(), JsReplace(kAddScriptModuleScript, script_url),
                      EXECUTE_SCRIPT_DEFAULT_OPTIONS, 1 /* world_id */)
                   .ExtractBool());
}

// Verify that Trusted Types will block assignment to a dangerous sink
// on WebUI by default.
IN_PROC_BROWSER_TEST_F(WebUISecurityTest, BlockSinkAssignmentWithTrustedTypes) {
  ASSERT_TRUE(embedded_test_server()->Start());
  GURL test_url(GetWebUIURL("web-ui/title1.html"));

  EXPECT_TRUE(NavigateToURL(shell(), test_url));

  const char kDangerousSinkUse[] =
      "(() => {"
      "  try {"
      "    document.body.innerHTML = 1;"
      "    throw 'Assignment should have blocked';"
      "  } catch(e) {"
      "    return 'Assignment blocked';"
      "  }"
      "})();";
  {
    WebContentsConsoleObserver console_observer(shell()->web_contents());
    console_observer.SetPattern(
        "This document requires 'TrustedHTML' assignment.");

    EXPECT_EQ("Assignment blocked",
              EvalJs(shell(), kDangerousSinkUse, EXECUTE_SCRIPT_DEFAULT_OPTIONS,
                     1 /* world_id */));
    console_observer.Wait();
  }
}

namespace {
class UntrustedSourceWithCorsSupport : public URLDataSource {
 public:
  static std::unique_ptr<UntrustedSourceWithCorsSupport> CreateForHost(
      std::string host) {
    std::string source_name = base::StrCat(
        {kChromeUIUntrustedScheme, url::kStandardSchemeSeparator, host, "/"});
    return std::make_unique<UntrustedSourceWithCorsSupport>(source_name);
  }
  explicit UntrustedSourceWithCorsSupport(std::string name) : name_(name) {}
  UntrustedSourceWithCorsSupport& operator=(
      const UntrustedSourceWithCorsSupport&) = delete;
  UntrustedSourceWithCorsSupport(const UntrustedSourceWithCorsSupport&) =
      delete;
  ~UntrustedSourceWithCorsSupport() override = default;

  // URLDataSource:
  std::string GetSource() override { return name_; }
  std::string GetAccessControlAllowOriginForOrigin(
      const std::string& origin) override {
    return origin;
  }
  std::string GetMimeType(const std::string& path) override {
    return "text/html";
  }
  void StartDataRequest(const GURL& url,
                        const WebContents::Getter& wc_getter,
                        GotDataCallback callback) override {
    std::string dummy_html = "<html><body>dummy</body></html>";
    scoped_refptr<base::RefCountedString> response =
        base::RefCountedString::TakeString(&dummy_html);
    std::move(callback).Run(response.get());
  }

 private:
  std::string name_;
};

enum FetchMode { SAME_ORIGIN, CORS, NO_CORS };

EvalJsResult PerformFetch(Shell* shell,
                          const GURL& fetch_url,
                          FetchMode fetch_mode = FetchMode::CORS) {
  std::string fetch_mode_string;
  switch (fetch_mode) {
    case SAME_ORIGIN:
      fetch_mode_string = "same-origin";
      break;
    case CORS:
      fetch_mode_string = "cors";
      break;
    case NO_CORS:
      fetch_mode_string = "no-cors";
      break;
    default:
      NOTREACHED();
  }
  const char kFetchRequestScript[] =
      "fetch($1, {mode: $2}).then("
      "  response => 'success',"
      "  error => error.message"
      ");";

  return EvalJs(shell,
                JsReplace(kFetchRequestScript, fetch_url, fetch_mode_string),
                EXECUTE_SCRIPT_DEFAULT_OPTIONS, 1 /* world_id */);
}
}  // namespace

// Verify fetch request from web pages to chrome-untrusted:// is blocked,
// because web pages don't have WebUIURLLoaderFactory for chrome-untrusted://
// scheme.
IN_PROC_BROWSER_TEST_F(WebUISecurityTest,
                       DisallowWebPageFetchRequestToChromeUntrusted) {
  const GURL untrusted_url = GURL("chrome-untrusted://test/title1.html");
  AddUntrustedDataSource(shell()->web_contents()->GetBrowserContext(),
                         untrusted_url.host());
  ASSERT_TRUE(embedded_test_server()->Start());

  const GURL web_url = embedded_test_server()->GetURL("/title2.html");
  EXPECT_TRUE(NavigateToURL(shell(), web_url));

  {
    DevToolsInspectorLogWatcher log_watcher(shell()->web_contents());
    EXPECT_EQ("Failed to fetch",
              PerformFetch(shell(), untrusted_url, FetchMode::CORS));
    log_watcher.FlushAndStopWatching();

    EXPECT_EQ(log_watcher.last_message(),
              "Failed to load resource: net::ERR_UNKNOWN_URL_SCHEME");
  }

  {
    DevToolsInspectorLogWatcher log_watcher(shell()->web_contents());
    EXPECT_EQ("Failed to fetch",
              PerformFetch(shell(), untrusted_url, FetchMode::NO_CORS));
    log_watcher.FlushAndStopWatching();

    EXPECT_EQ(log_watcher.last_message(),
              "Failed to load resource: net::ERR_UNKNOWN_URL_SCHEME");
  }
}

// Verify a chrome-untrusted:// document can fetch itself.
IN_PROC_BROWSER_TEST_F(WebUISecurityTest, ChromeUntrustedFetchRequestToSelf) {
  const GURL untrusted_url = GURL("chrome-untrusted://test/title1.html");
  AddUntrustedDataSource(shell()->web_contents()->GetBrowserContext(),
                         untrusted_url.host());

  EXPECT_TRUE(NavigateToURL(shell(), untrusted_url));
  EXPECT_EQ("success",
            PerformFetch(shell(), untrusted_url, FetchMode::SAME_ORIGIN));
}

// Verify cross-origin fetch request from a chrome-untrusted:// page to another
// chrome-untrusted:// page is blocked by the default "default-src 'self'"
// Content Security Policy on URLDataSource.
IN_PROC_BROWSER_TEST_F(
    WebUISecurityTest,
    DisallowCrossOriginFetchRequestToChromeUntrustedByDefault) {
  const GURL untrusted_url1 = GURL("chrome-untrusted://test1/title1.html");
  AddUntrustedDataSource(shell()->web_contents()->GetBrowserContext(),
                         untrusted_url1.host());
  const GURL untrusted_url2 = GURL("chrome-untrusted://test2/title2.html");
  URLDataSource::Add(
      shell()->web_contents()->GetBrowserContext(),
      UntrustedSourceWithCorsSupport::CreateForHost(untrusted_url2.host()));

  EXPECT_TRUE(NavigateToURL(shell(), untrusted_url1));

  {
    WebContentsConsoleObserver console_observer(shell()->web_contents());
    EXPECT_EQ("Failed to fetch",
              PerformFetch(shell(), untrusted_url2, FetchMode::CORS));
    console_observer.Wait();
    EXPECT_EQ(console_observer.GetMessageAt(0),
              base::StringPrintf(
                  "Refused to connect to '%s' because it violates the "
                  "following Content Security Policy directive: \"default-src "
                  "'self'\". Note that 'connect-src' was not explicitly set, "
                  "so 'default-src' is used as a fallback.\n",
                  untrusted_url2.spec().c_str()));
  }

  {
    WebContentsConsoleObserver console_observer(shell()->web_contents());
    EXPECT_EQ("Failed to fetch",
              PerformFetch(shell(), untrusted_url2, FetchMode::NO_CORS));
    console_observer.Wait();
    EXPECT_EQ(console_observer.GetMessageAt(0),
              base::StringPrintf(
                  "Refused to connect to '%s' because it violates the "
                  "following Content Security Policy directive: \"default-src "
                  "'self'\". Note that 'connect-src' was not explicitly set, "
                  "so 'default-src' is used as a fallback.\n",
                  untrusted_url2.spec().c_str()));
  }
}

// Verify cross-origin fetch request from a chrome-untrusted:// page to another
// chrome-untrusted:// page succeeds if Content Security Policy allows it.
IN_PROC_BROWSER_TEST_F(WebUISecurityTest,
                       CrossOriginFetchRequestToChromeUntrusted) {
  TestUntrustedDataSourceCSP csp;
  csp.default_src = "default-src chrome-untrusted://test2;";
  const GURL untrusted_url1 = GURL("chrome-untrusted://test1/title1.html");
  AddUntrustedDataSource(shell()->web_contents()->GetBrowserContext(),
                         untrusted_url1.host(), csp);

  const GURL untrusted_url2 = GURL("chrome-untrusted://test2/title2.html");
  URLDataSource::Add(
      shell()->web_contents()->GetBrowserContext(),
      UntrustedSourceWithCorsSupport::CreateForHost(untrusted_url2.host()));

  EXPECT_TRUE(NavigateToURL(shell(), untrusted_url1));
  EXPECT_EQ("success", PerformFetch(shell(), untrusted_url2, FetchMode::CORS));
  EXPECT_EQ("success",
            PerformFetch(shell(), untrusted_url2, FetchMode::NO_CORS));
}

// Verify fetch request from a chrome-untrusted:// page to a chrome:// page
// is blocked because chrome-untrusted:// pages don't have WebUIURLLoaderFactory
// for chrome:// scheme, even if CSP allows this.
IN_PROC_BROWSER_TEST_F(WebUISecurityTest,
                       DisallowChromeUntrustedFetchRequestToChrome) {
  TestUntrustedDataSourceCSP csp;
  csp.default_src = "default-src chrome://webui;";
  const GURL untrusted_url = GURL("chrome-untrusted://test1/title1.html");
  AddUntrustedDataSource(shell()->web_contents()->GetBrowserContext(),
                         untrusted_url.host(), csp);

  const GURL chrome_url = GURL("chrome://webui/title2.html");

  EXPECT_TRUE(NavigateToURL(shell(), untrusted_url));

  {
    WebContentsConsoleObserver console_observer(shell()->web_contents());
    EXPECT_EQ("Failed to fetch",
              PerformFetch(shell(), chrome_url, FetchMode::CORS));
    console_observer.Wait();
    EXPECT_EQ(console_observer.GetMessageAt(0),
              base::StringPrintf("Fetch API cannot load %s. URL scheme must be "
                                 "\"http\" or \"https\" for CORS request.",
                                 chrome_url.spec().c_str()));
  }

  {
    WebContentsConsoleObserver console_observer(shell()->web_contents());
    EXPECT_EQ("Failed to fetch",
              PerformFetch(shell(), chrome_url, FetchMode::NO_CORS));
    console_observer.Wait();
    EXPECT_EQ(
        console_observer.GetMessageAt(0),
        base::StringPrintf(
            "Fetch API cannot load %s. URL scheme \"chrome\" is not supported.",
            chrome_url.spec().c_str()));
  }
}

namespace {
EvalJsResult PerformXHRRequest(Shell* shell, const GURL& xhr_url) {
  const char kXHRRequestScript[] =
      "new Promise((resolve) => {"
      "  const xhr = new XMLHttpRequest();"
      "  xhr.open('GET', $1);"
      "  xhr.onload = () => resolve('success');"
      "  xhr.onerror = progress_event => resolve(progress_event.type);"
      "  xhr.send();"
      "}); ";

  return EvalJs(shell, JsReplace(kXHRRequestScript, xhr_url),
                EXECUTE_SCRIPT_DEFAULT_OPTIONS, 1 /* world_id */);
}
}  // namespace

// Verify XHR request from web pages to chrome-untrusted:// is blocked, because
// web pages don't have WebUIURLLoader required to load chrome-untrusted://
// resources.
IN_PROC_BROWSER_TEST_F(WebUISecurityTest,
                       DisallowWebPageXHRRequestToChromeUntrusted) {
  const GURL untrusted_url = GURL("chrome-untrusted://test/title1.html");
  AddUntrustedDataSource(shell()->web_contents()->GetBrowserContext(),
                         untrusted_url.host());
  ASSERT_TRUE(embedded_test_server()->Start());
  const GURL web_url = embedded_test_server()->GetURL("/title2.html");

  EXPECT_TRUE(NavigateToURL(shell(), web_url));

  DevToolsInspectorLogWatcher log_watcher(shell()->web_contents());
  EXPECT_EQ("error", PerformXHRRequest(shell(), untrusted_url));
  log_watcher.FlushAndStopWatching();

  EXPECT_EQ(log_watcher.last_message(),
            "Failed to load resource: net::ERR_UNKNOWN_URL_SCHEME");
}

// Verify a chrome-untrusted:// document can XHR itself.
IN_PROC_BROWSER_TEST_F(WebUISecurityTest,
                       AllowChromeUntrustedXHRRequestToSelf) {
  const GURL untrusted_url = GURL("chrome-untrusted://test/title1.html");
  AddUntrustedDataSource(shell()->web_contents()->GetBrowserContext(),
                         untrusted_url.host());

  EXPECT_TRUE(NavigateToURL(shell(), untrusted_url));
  EXPECT_EQ("success", PerformXHRRequest(shell(), untrusted_url));
}

// Verify cross-origin XHR request from a chrome-untrusted:// page to another
// chrome-untrusted:// page is blocked by "default-src 'self';" Content Security
// Policy.
IN_PROC_BROWSER_TEST_F(
    WebUISecurityTest,
    DisallowCrossOriginXHRRequestToChromeUntrustedByDefault) {
  const GURL untrusted_url1 = GURL("chrome-untrusted://test1/title1.html");
  AddUntrustedDataSource(shell()->web_contents()->GetBrowserContext(),
                         untrusted_url1.host());
  const GURL untrusted_url2 = GURL("chrome-untrusted://test2/");
  URLDataSource::Add(
      shell()->web_contents()->GetBrowserContext(),
      UntrustedSourceWithCorsSupport::CreateForHost(untrusted_url2.host()));

  EXPECT_TRUE(NavigateToURL(shell(), untrusted_url1));

  WebContentsConsoleObserver console_observer(shell()->web_contents());
  EXPECT_EQ("error", PerformXHRRequest(shell(), untrusted_url2));
  console_observer.Wait();
  EXPECT_EQ(console_observer.GetMessageAt(0),
            base::StringPrintf(
                "Refused to connect to '%s' because it violates the "
                "following Content Security Policy directive: \"default-src "
                "'self'\". Note that 'connect-src' was not explicitly set, "
                "so 'default-src' is used as a fallback.\n",
                untrusted_url2.spec().c_str()));
}

// Verify cross-origin XHR request from a chrome-untrusted:// page to another
// chrome-untrusted:// page is successful, if Content Security Policy allows it,
// and the requested resource presents an Access-Control-Allow-Origin header.
IN_PROC_BROWSER_TEST_F(
    WebUISecurityTest,
    CrossOriginXHRRequestToChromeUntrustedIfContenSecurityPolicyAllowsIt) {
  TestUntrustedDataSourceCSP csp;
  csp.default_src = "default-src chrome-untrusted://test2;";
  const GURL untrusted_url1 = GURL("chrome-untrusted://test1/title1.html");
  AddUntrustedDataSource(shell()->web_contents()->GetBrowserContext(),
                         untrusted_url1.host(), csp);
  const GURL untrusted_url2 = GURL("chrome-untrusted://test2/");
  URLDataSource::Add(
      shell()->web_contents()->GetBrowserContext(),
      UntrustedSourceWithCorsSupport::CreateForHost(untrusted_url2.host()));

  EXPECT_TRUE(NavigateToURL(shell(), untrusted_url1));
  EXPECT_EQ("success", PerformXHRRequest(shell(), untrusted_url2));
}

// Verify XHR request from a chrome-untrusted:// page to a chrome:// page is
// blocked, even if CSP allows this.
IN_PROC_BROWSER_TEST_F(WebUISecurityTest,
                       DisallowChromeUntrustedXHRRequestToChrome) {
  TestUntrustedDataSourceCSP csp;
  csp.default_src = "default-src chrome://webui;";
  const GURL untrusted_url = GURL("chrome-untrusted://test1/title1.html");
  AddUntrustedDataSource(shell()->web_contents()->GetBrowserContext(),
                         untrusted_url.host(), csp);

  const GURL chrome_url = GURL("chrome://webui/title2.html");

  EXPECT_TRUE(NavigateToURL(shell(), untrusted_url));

  WebContentsConsoleObserver console_observer(shell()->web_contents());
  EXPECT_EQ("error", PerformXHRRequest(shell(), chrome_url));
  console_observer.Wait();
  EXPECT_EQ(console_observer.GetMessageAt(0),
            base::StringPrintf("Not allowed to load local resource: %s",
                               chrome_url.spec().c_str()));
}

}  // namespace content
