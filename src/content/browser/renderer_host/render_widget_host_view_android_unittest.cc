// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/renderer_host/render_widget_host_view_android.h"

#include <memory>

#include "cc/layers/deadline_policy.h"
#include "cc/layers/layer.h"
#include "components/viz/common/surfaces/local_surface_id.h"
#include "content/browser/renderer_host/agent_scheduling_group_host.h"
#include "content/browser/renderer_host/mock_render_widget_host.h"
#include "content/public/test/browser_task_environment.h"
#include "content/public/test/mock_render_process_host.h"
#include "content/public/test/test_browser_context.h"
#include "content/test/mock_render_widget_host_delegate.h"
#include "content/test/test_view_android_delegate.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "ui/android/view_android.h"
#include "ui/android/window_android.h"

namespace content {

class RenderWidgetHostViewAndroidTest : public testing::Test {
 public:
  RenderWidgetHostViewAndroidTest();
  ~RenderWidgetHostViewAndroidTest() override {}

  RenderWidgetHostViewAndroid* render_widget_host_view_android() {
    return render_widget_host_view_android_;
  }

  // Directly map to RenderWidgetHostViewAndroid methods.
  bool SynchronizeVisualProperties(
      const cc::DeadlinePolicy& deadline_policy,
      const base::Optional<viz::LocalSurfaceId>& child_local_surface_id);
  void WasEvicted();
  ui::ViewAndroid* GetViewAndroid() { return &native_view_; }

 protected:
  // testing::Test:
  void SetUp() override;
  void TearDown() override;

  ui::ViewAndroid* parent_view() { return &parent_view_; }

  std::unique_ptr<TestViewAndroidDelegate> test_view_android_delegate_;

 private:
  std::unique_ptr<TestBrowserContext> browser_context_;
  MockRenderProcessHost* process_;  // Deleted automatically by the widget.
  std::unique_ptr<AgentSchedulingGroupHost> agent_scheduling_group_;
  std::unique_ptr<MockRenderWidgetHostDelegate> delegate_;
  scoped_refptr<cc::Layer> parent_layer_;
  scoped_refptr<cc::Layer> layer_;
  ui::ViewAndroid parent_view_;
  ui::ViewAndroid native_view_;
  std::unique_ptr<MockRenderWidgetHost> host_;
  RenderWidgetHostViewAndroid* render_widget_host_view_android_;

  BrowserTaskEnvironment task_environment_;

  DISALLOW_COPY_AND_ASSIGN(RenderWidgetHostViewAndroidTest);
};

RenderWidgetHostViewAndroidTest::RenderWidgetHostViewAndroidTest()
    : parent_view_(ui::ViewAndroid::LayoutType::NORMAL),
      native_view_(ui::ViewAndroid::LayoutType::NORMAL) {}

bool RenderWidgetHostViewAndroidTest::SynchronizeVisualProperties(
    const cc::DeadlinePolicy& deadline_policy,
    const base::Optional<viz::LocalSurfaceId>& child_local_surface_id) {
  return render_widget_host_view_android_->SynchronizeVisualProperties(
      deadline_policy, child_local_surface_id);
}

void RenderWidgetHostViewAndroidTest::WasEvicted() {
  render_widget_host_view_android_->WasEvicted();
}

void RenderWidgetHostViewAndroidTest::SetUp() {
  browser_context_.reset(new TestBrowserContext());
  delegate_.reset(new MockRenderWidgetHostDelegate());
  process_ = new MockRenderProcessHost(browser_context_.get());
  agent_scheduling_group_ =
      std::make_unique<AgentSchedulingGroupHost>(*process_);
  host_.reset(MockRenderWidgetHost::Create(
      delegate_.get(), *agent_scheduling_group_, process_->GetNextRoutingID()));
  parent_layer_ = cc::Layer::Create();
  parent_view_.SetLayer(parent_layer_);
  layer_ = cc::Layer::Create();
  native_view_.SetLayer(layer_);
  parent_view_.AddChild(&native_view_);
  EXPECT_EQ(&parent_view_, native_view_.parent());
  render_widget_host_view_android_ =
      new RenderWidgetHostViewAndroid(host_.get(), &native_view_);
  test_view_android_delegate_.reset(new TestViewAndroidDelegate());
}

void RenderWidgetHostViewAndroidTest::TearDown() {
  render_widget_host_view_android_->Destroy();
  host_.reset();
  delegate_.reset();
  agent_scheduling_group_ = nullptr;
  process_ = nullptr;
  browser_context_.reset();
}

// Tests that when a child responds to a Surface Synchronization message, while
// we are evicted, that we do not attempt to embed an invalid
// viz::LocalSurfaceId. This test should not crash.
TEST_F(RenderWidgetHostViewAndroidTest, NoSurfaceSynchronizationWhileEvicted) {
  // Android default host and views initialize as visible.
  RenderWidgetHostViewAndroid* rwhva = render_widget_host_view_android();
  EXPECT_TRUE(rwhva->IsShowing());
  const viz::LocalSurfaceId initial_local_surface_id =
      rwhva->GetLocalSurfaceId();
  EXPECT_TRUE(initial_local_surface_id.is_valid());

  // Evicting while hidden should invalidate the current viz::LocalSurfaceId.
  rwhva->Hide();
  EXPECT_FALSE(rwhva->IsShowing());
  WasEvicted();
  EXPECT_FALSE(rwhva->GetLocalSurfaceId().is_valid());

  // When a child acknowledges a Surface Synchronization message, and has no new
  // properties to change, it responds with the original viz::LocalSurfaceId.
  // If we are evicted, we should not attempt to embed our invalid id. Nor
  // should we continue the synchronization process. This should not cause a
  // crash in DelegatedFrameHostAndroid.
  EXPECT_FALSE(SynchronizeVisualProperties(
      cc::DeadlinePolicy::UseDefaultDeadline(), initial_local_surface_id));
}

// Tests insetting the Visual Viewport.
TEST_F(RenderWidgetHostViewAndroidTest, InsetVisualViewport) {
  // Android default viewport should not have an inset bottom.
  RenderWidgetHostViewAndroid* rwhva = render_widget_host_view_android();
  EXPECT_EQ(0, GetViewAndroid()->GetViewportInsetBottom());

  // Set up SurfaceId checking.
  const viz::LocalSurfaceId original_local_surface_id =
      rwhva->GetLocalSurfaceId();

  // Set up our test delegate connected to this ViewAndroid.
  test_view_android_delegate_->SetupTestDelegate(GetViewAndroid());
  EXPECT_EQ(0, GetViewAndroid()->GetViewportInsetBottom());

  JNIEnv* env = base::android::AttachCurrentThread();

  // Now inset the bottom and make sure the surface changes, and the inset is
  // known to our ViewAndroid.
  test_view_android_delegate_->InsetViewportBottom(100);
  EXPECT_EQ(100, GetViewAndroid()->GetViewportInsetBottom());
  rwhva->OnViewportInsetBottomChanged(env, nullptr);
  viz::LocalSurfaceId inset_surface = rwhva->GetLocalSurfaceId();
  EXPECT_TRUE(inset_surface.IsNewerThan(original_local_surface_id));

  // Reset the bottom; should go back to the original inset and have a new
  // surface.
  test_view_android_delegate_->InsetViewportBottom(0);
  rwhva->OnViewportInsetBottomChanged(env, nullptr);
  EXPECT_EQ(0, GetViewAndroid()->GetViewportInsetBottom());
  EXPECT_TRUE(rwhva->GetLocalSurfaceId().IsNewerThan(inset_surface));
}

TEST_F(RenderWidgetHostViewAndroidTest, HideWindowRemoveViewAddViewShowWindow) {
  std::unique_ptr<ui::WindowAndroid> window(
      ui::WindowAndroid::CreateForTesting());
  window->AddChild(parent_view());
  EXPECT_TRUE(render_widget_host_view_android()->IsShowing());
  // The layer should be visible once attached to a window.
  EXPECT_FALSE(render_widget_host_view_android()
                   ->GetNativeView()
                   ->GetLayer()
                   ->hide_layer_and_subtree());

  // Hiding the window should and removing the view should hide the layer.
  window->OnVisibilityChanged(nullptr, nullptr, false);
  parent_view()->RemoveFromParent();
  EXPECT_TRUE(render_widget_host_view_android()->IsShowing());
  EXPECT_TRUE(render_widget_host_view_android()
                  ->GetNativeView()
                  ->GetLayer()
                  ->hide_layer_and_subtree());

  // Adding the view back to a window and notifying the window is visible should
  // make the layer visible again.
  window->AddChild(parent_view());
  window->OnVisibilityChanged(nullptr, nullptr, true);
  EXPECT_TRUE(render_widget_host_view_android()->IsShowing());
  EXPECT_FALSE(render_widget_host_view_android()
                   ->GetNativeView()
                   ->GetLayer()
                   ->hide_layer_and_subtree());
}

}  // namespace content
