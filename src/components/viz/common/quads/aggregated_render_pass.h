// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_VIZ_COMMON_QUADS_AGGREGATED_RENDER_PASS_H_
#define COMPONENTS_VIZ_COMMON_QUADS_AGGREGATED_RENDER_PASS_H_

#include <stddef.h>

#include <memory>
#include <utility>
#include <vector>

#include "base/callback.h"
#include "base/hash/hash.h"
#include "base/macros.h"
#include "base/util/type_safety/id_type.h"
#include "cc/base/list_container.h"
#include "cc/paint/filter_operations.h"
#include "components/viz/common/quads/draw_quad.h"
#include "components/viz/common/quads/largest_draw_quad.h"
#include "components/viz/common/quads/quad_list.h"
#include "components/viz/common/quads/render_pass_internal.h"
#include "components/viz/common/viz_common_export.h"
#include "ui/gfx/display_color_spaces.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/rrect_f.h"
#include "ui/gfx/transform.h"

namespace viz {
class AggregatedRenderPass;
class CompositorRenderPassDrawQuad;
class AggregatedRenderPassDrawQuad;

using AggregatedRenderPassId = util::IdTypeU64<AggregatedRenderPass>;

// This class represents a render pass that is a result of aggregating render
// passes from all of the relevant surfaces. It is _not_ mojo-serializable since
// it is local to the viz process. It has a unique AggregatedRenderPassId across
// all of the AggregatedRenderPasses.
class VIZ_COMMON_EXPORT AggregatedRenderPass : public RenderPassInternal {
 public:
  ~AggregatedRenderPass();

  AggregatedRenderPass();
  AggregatedRenderPass(size_t shared_quad_state_size, size_t draw_quad_size);

  void SetNew(AggregatedRenderPassId id,
              const gfx::Rect& output_rect,
              const gfx::Rect& damage_rect,
              const gfx::Transform& transform_to_root_target);

  void SetAll(AggregatedRenderPassId id,
              const gfx::Rect& output_rect,
              const gfx::Rect& damage_rect,
              const gfx::Transform& transform_to_root_target,
              const cc::FilterOperations& filters,
              const cc::FilterOperations& backdrop_filters,
              const base::Optional<gfx::RRectF>& backdrop_filter_bounds,
              gfx::ContentColorUsage content_color_usage,
              bool has_transparent_background,
              bool cache_render_pass,
              bool has_damage_from_contributing_content,
              bool generate_mipmap);

  AggregatedRenderPassDrawQuad* CopyFromAndAppendRenderPassDrawQuad(
      const CompositorRenderPassDrawQuad* quad,
      AggregatedRenderPassId render_pass_id);
  AggregatedRenderPassDrawQuad* CopyFromAndAppendRenderPassDrawQuad(
      const AggregatedRenderPassDrawQuad* quad);
  DrawQuad* CopyFromAndAppendDrawQuad(const DrawQuad* quad);

  // A shallow copy of the render pass, which does not include its quads or copy
  // requests.
  std::unique_ptr<AggregatedRenderPass> Copy(
      AggregatedRenderPassId new_id) const;

  // A deep copy of the render pass that includes quads.
  std::unique_ptr<AggregatedRenderPass> DeepCopy() const;

  template <typename DrawQuadType>
  DrawQuadType* CreateAndAppendDrawQuad() {
    static_assert(
        !std::is_same<DrawQuadType, CompositorRenderPassDrawQuad>::value,
        "cannot create CompositorRenderPassDrawQuad in AggregatedRenderPass");
    return quad_list.AllocateAndConstruct<DrawQuadType>();
  }

  // Uniquely identifies the render pass in the aggregated frame.
  AggregatedRenderPassId id;

  // The type of color content present in this RenderPass.
  gfx::ContentColorUsage content_color_usage = gfx::ContentColorUsage::kSRGB;

  // Indicates current RenderPass is a color conversion pass.
  bool is_color_conversion_pass = false;

 private:
  template <typename DrawQuadType>
  DrawQuadType* CopyFromAndAppendTypedDrawQuad(const DrawQuad* quad) {
    static_assert(
        !std::is_same<DrawQuadType, CompositorRenderPassDrawQuad>::value,
        "cannot copy CompositorRenderPassDrawQuad type into "
        "AggregatedRenderPass");
    return quad_list.AllocateAndCopyFrom(DrawQuadType::MaterialCast(quad));
  }

  DISALLOW_COPY_AND_ASSIGN(AggregatedRenderPass);
};

using AggregatedRenderPassList =
    std::vector<std::unique_ptr<AggregatedRenderPass>>;

}  // namespace viz
#endif  // COMPONENTS_VIZ_COMMON_QUADS_AGGREGATED_RENDER_PASS_H_
