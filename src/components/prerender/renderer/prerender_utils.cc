// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/prerender/renderer/prerender_utils.h"

#include "components/prerender/renderer/prerender_helper.h"
#include "content/public/common/page_visibility_state.h"
#include "content/public/renderer/render_frame.h"
#include "content/public/renderer/render_view.h"
#include "content/public/renderer/render_view_observer.h"
#include "third_party/blink/public/web/web_view.h"

namespace prerender {

namespace {

// Defers media player loading in background pages until they're visible.
class MediaLoadDeferrer : public content::RenderViewObserver {
 public:
  MediaLoadDeferrer(content::RenderView* render_view,
                    base::OnceClosure continue_loading_cb)
      : content::RenderViewObserver(render_view),
        continue_loading_cb_(std::move(continue_loading_cb)) {}
  ~MediaLoadDeferrer() override = default;

  // content::RenderFrameObserver implementation:
  void OnDestruct() override { delete this; }
  void OnPageVisibilityChanged(
      content::PageVisibilityState visibility_state) override {
    if (visibility_state != content::PageVisibilityState::kVisible)
      return;
    std::move(continue_loading_cb_).Run();
    delete this;
  }

 private:
  base::OnceClosure continue_loading_cb_;

  DISALLOW_COPY_AND_ASSIGN(MediaLoadDeferrer);
};

}  // namespace

bool DeferMediaLoad(content::RenderFrame* render_frame,
                    bool has_played_media_before,
                    base::OnceClosure closure) {
  // Don't allow autoplay/autoload of media resources in a page that is hidden
  // and has never played any media before.  We want to allow future loads even
  // when hidden to allow playlist-like functionality.
  //
  // NOTE: This is also used to defer media loading for prerender.
  if ((render_frame->GetRenderView()->GetWebView()->GetVisibilityState() !=
           content::PageVisibilityState::kVisible &&
       !has_played_media_before) ||
      prerender::PrerenderHelper::IsPrerendering(render_frame)) {
    new MediaLoadDeferrer(render_frame->GetRenderView(), std::move(closure));
    return true;
  }

  std::move(closure).Run();
  return false;
}

}  // namespace prerender
