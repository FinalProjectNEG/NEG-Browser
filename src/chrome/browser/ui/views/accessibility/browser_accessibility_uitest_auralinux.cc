// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <atk/atk.h>
#include <stddef.h>

#include "base/macros.h"
#include "chrome/browser/devtools/devtools_window_testing.h"
#include "chrome/browser/ui/browser.h"
#include "chrome/browser/ui/browser_window.h"
#include "chrome/browser/ui/tab_modal_confirm_dialog.h"
#include "chrome/browser/ui/views/frame/browser_view.h"
#include "chrome/test/base/in_process_browser_test.h"
#include "content/public/browser/render_widget_host_view.h"
#include "content/public/browser/web_contents.h"
#include "content/public/test/browser_test.h"
#include "ui/accessibility/platform/ax_platform_node.h"

class AuraLinuxAccessibilityInProcessBrowserTest : public InProcessBrowserTest {
 public:
  void SetUp() override {
    ui::AXPlatformNode::NotifyAddAXModeFlags(ui::kAXModeComplete);
    InProcessBrowserTest::SetUp();
  }

 protected:
  AuraLinuxAccessibilityInProcessBrowserTest() = default;

  void VerifyEmbedRelationships();

 private:
  DISALLOW_COPY_AND_ASSIGN(AuraLinuxAccessibilityInProcessBrowserTest);
};

IN_PROC_BROWSER_TEST_F(AuraLinuxAccessibilityInProcessBrowserTest,
                       IndexInParent) {
  AtkObject* native_view_accessible =
      static_cast<BrowserView*>(browser()->window())->GetNativeViewAccessible();
  EXPECT_NE(nullptr, native_view_accessible);

  int n_children = atk_object_get_n_accessible_children(native_view_accessible);
  for (int i = 0; i < n_children; i++) {
    AtkObject* child =
        atk_object_ref_accessible_child(native_view_accessible, i);

    int index_in_parent = atk_object_get_index_in_parent(child);
    ASSERT_NE(-1, index_in_parent);
    ASSERT_EQ(i, index_in_parent);

    g_object_unref(child);
  }
}

class TestTabModalConfirmDialogDelegate : public TabModalConfirmDialogDelegate {
 public:
  explicit TestTabModalConfirmDialogDelegate(content::WebContents* contents)
      : TabModalConfirmDialogDelegate(contents) {}
  base::string16 GetTitle() override {
    return base::ASCIIToUTF16("Dialog Title");
  }
  base::string16 GetDialogMessage() override { return base::string16(); }

  DISALLOW_COPY_AND_ASSIGN(TestTabModalConfirmDialogDelegate);
};

// Open a tab-modal dialog and test IndexInParent with the modal dialog.
IN_PROC_BROWSER_TEST_F(AuraLinuxAccessibilityInProcessBrowserTest,
                       IndexInParentWithModal) {
  BrowserView* browser_view = BrowserView::GetBrowserViewForBrowser(browser());
  AtkObject* native_view_accessible =
      browser_view->GetWidget()->GetRootView()->GetNativeViewAccessible();
  EXPECT_NE(nullptr, native_view_accessible);

  // The root view has a child that is a client role for Chromium.
  int n_children = atk_object_get_n_accessible_children(native_view_accessible);
  ASSERT_EQ(1, n_children);
  AtkObject* client =
      atk_object_ref_accessible_child(native_view_accessible, 0);
  ASSERT_EQ(0, atk_object_get_index_in_parent(client));

  // Opens a tab-modal dialog.
  content::WebContents* contents = browser_view->GetActiveWebContents();
  auto delegate = std::make_unique<TestTabModalConfirmDialogDelegate>(contents);
  TabModalConfirmDialog* dialog =
      TabModalConfirmDialog::Create(std::move(delegate), contents);

  // The root view still has one child that is a dialog role since if it has a
  // modal dialog it hides the rest of the children.
  n_children = atk_object_get_n_accessible_children(native_view_accessible);
  ASSERT_EQ(1, n_children);
  AtkObject* dialog_node =
      atk_object_ref_accessible_child(native_view_accessible, 0);
  ASSERT_EQ(0, atk_object_get_index_in_parent(dialog_node));

  // The client has an invalid value for the index in parent since it's hidden
  // by the dialog.
  ASSERT_EQ(-1, atk_object_get_index_in_parent(client));

  dialog->CloseDialog();
  // It has a valid value for the client after the dialog is closed.
  ASSERT_EQ(0, atk_object_get_index_in_parent(client));

  g_object_unref(client);
  g_object_unref(dialog_node);
}

static AtkObject* FindParentFrame(AtkObject* object) {
  while (object) {
    if (atk_object_get_role(object) == ATK_ROLE_FRAME)
      return object;
    object = atk_object_get_parent(object);
  }

  return nullptr;
}

void AuraLinuxAccessibilityInProcessBrowserTest::VerifyEmbedRelationships() {
  AtkObject* native_view_accessible =
      static_cast<BrowserView*>(browser()->window())->GetNativeViewAccessible();
  EXPECT_NE(nullptr, native_view_accessible);

  AtkObject* window = FindParentFrame(native_view_accessible);
  EXPECT_NE(nullptr, window);

  AtkRelationSet* relations = atk_object_ref_relation_set(window);
  ASSERT_TRUE(atk_relation_set_contains(relations, ATK_RELATION_EMBEDS));

  AtkRelation* embeds_relation =
      atk_relation_set_get_relation_by_type(relations, ATK_RELATION_EMBEDS);
  EXPECT_NE(nullptr, embeds_relation);

  GPtrArray* targets = atk_relation_get_target(embeds_relation);
  EXPECT_NE(nullptr, targets);
  EXPECT_EQ(1u, targets->len);

  AtkObject* target = static_cast<AtkObject*>(g_ptr_array_index(targets, 0));

  EXPECT_NE(nullptr, target);

  content::WebContents* active_web_contents =
      browser()->tab_strip_model()->GetActiveWebContents();
  ASSERT_EQ(target, active_web_contents->GetRenderWidgetHostView()
                        ->GetNativeViewAccessible());

  g_object_unref(relations);

  relations = atk_object_ref_relation_set(target);
  ASSERT_TRUE(atk_relation_set_contains(relations, ATK_RELATION_EMBEDDED_BY));

  AtkRelation* embedded_by_relation = atk_relation_set_get_relation_by_type(
      relations, ATK_RELATION_EMBEDDED_BY);
  EXPECT_NE(nullptr, embedded_by_relation);

  targets = atk_relation_get_target(embedded_by_relation);
  EXPECT_NE(nullptr, targets);
  EXPECT_EQ(1u, targets->len);

  target = static_cast<AtkObject*>(g_ptr_array_index(targets, 0));
  ASSERT_EQ(target, window);

  g_object_unref(relations);
}

IN_PROC_BROWSER_TEST_F(AuraLinuxAccessibilityInProcessBrowserTest,
                       EmbeddedRelationship) {
  // Force the creation of the document's native object which sets up the
  // relationship.
  content::WebContents* active_web_contents =
      browser()->tab_strip_model()->GetActiveWebContents();
  ASSERT_NE(nullptr, active_web_contents->GetRenderWidgetHostView()
                         ->GetNativeViewAccessible());

  GURL url(url::kAboutBlankURL);
  AddTabAtIndex(0, url, ui::PAGE_TRANSITION_LINK);
  EXPECT_EQ(2, browser()->tab_strip_model()->count());
  EXPECT_EQ(0, browser()->tab_strip_model()->active_index());

  VerifyEmbedRelationships();

  browser()->tab_strip_model()->ActivateTabAt(1);
  EXPECT_EQ(1, browser()->tab_strip_model()->active_index());

  VerifyEmbedRelationships();

  browser()->tab_strip_model()->ActivateTabAt(0);
  EXPECT_EQ(0, browser()->tab_strip_model()->active_index());

  VerifyEmbedRelationships();
}

// Tests that the embedded relationship is set on the main web contents when
// the DevTools is opened.
IN_PROC_BROWSER_TEST_F(AuraLinuxAccessibilityInProcessBrowserTest,
                       EmbeddedRelationshipWithDevTools) {
  // Force the creation of the document's native object which sets up the
  // relationship.
  content::WebContents* active_web_contents =
      browser()->tab_strip_model()->GetActiveWebContents();
  ASSERT_NE(nullptr, active_web_contents->GetRenderWidgetHostView()
                         ->GetNativeViewAccessible());
  EXPECT_EQ(1, browser()->tab_strip_model()->count());
  EXPECT_EQ(0, browser()->tab_strip_model()->active_index());

  // Opens DevTools docked.
  DevToolsWindow* devtools =
      DevToolsWindowTesting::OpenDevToolsWindowSync(browser(), true);
  VerifyEmbedRelationships();

  // Closes the DevTools window.
  DevToolsWindowTesting::CloseDevToolsWindowSync(devtools);
  VerifyEmbedRelationships();

  // Opens DevTools in a separate window.
  devtools = DevToolsWindowTesting::OpenDevToolsWindowSync(browser(), false);
  VerifyEmbedRelationships();

  // Closes the DevTools window.
  DevToolsWindowTesting::CloseDevToolsWindowSync(devtools);
  VerifyEmbedRelationships();
}
