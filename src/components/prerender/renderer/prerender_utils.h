// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_PRERENDER_RENDERER_PRERENDER_UTILS_H_
#define COMPONENTS_PRERENDER_RENDERER_PRERENDER_UTILS_H_

#include "base/callback_forward.h"

namespace content {
class RenderFrame;
}

namespace prerender {

// Defers media load for |render_frame| if necessary, and returns true if that
// has been done. Runs |closure| at the end of the operation regardless of
// return value.
bool DeferMediaLoad(content::RenderFrame* render_frame,
                    bool has_played_media_before,
                    base::OnceClosure closure);

}  // namespace prerender

#endif  // COMPONENTS_PRERENDER_RENDERER_PRERENDER_UTILS_H_
