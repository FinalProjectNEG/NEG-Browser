// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ASH_HUD_DISPLAY_GRAPH_H_
#define ASH_HUD_DISPLAY_GRAPH_H_

#include <vector>

#include "ash/hud_display/hud_constants.h"
#include "base/containers/ring_buffer.h"
#include "third_party/skia/include/core/SkColor.h"
#include "ui/gfx/geometry/point.h"
#include "ui/gfx/geometry/rect.h"

namespace gfx {
class Canvas;
}

namespace ash {
namespace hud_display {

class Graph {
 public:
  // Graph screen size (that is used in Layout()) should match (ring buffer
  // size - 1) to prevent scaling, because RingBuffer always keeps one element
  // unused.
  using Data = base::RingBuffer<float, kDefaultGraphWidth + 1>;

  enum class Baseline {
    BASELINE_BOTTOM,  // Positive values will be drawn from the bottom border
                      // up.
    BASELINE_TOP,     // Positive values will be drawn from the top border down.
  };

  // Whether to draw the graph as a filled polygon.
  enum class Fill {
    NONE,
    SOLID,
  };

  Graph(Baseline baseline, Fill fill, SkColor color);
  ~Graph();

  Graph(const Graph&) = delete;
  Graph& operator=(const Graph&) = delete;

  // |value| must be normalized to [0,1]. When graphs are drawn stacked,
  // the full stack must be normalized.
  // |unscaled_value| is used to label graph values to the user.
  void AddValue(float value, float unscaled_value);
  void Layout(const gfx::Rect& graph_bounds, const Graph* base);
  void Draw(gfx::Canvas* canvas) const;

  const std::vector<SkPoint>& top_path() const { return top_path_; }

  size_t GetDataBufferSize() const { return data_.BufferSize(); }

  SkColor color() const { return color_; }

  // Returns value from |unscaled_data_|.
  // |index| is always interpreted as "negative", i.e. "0" - current data, "1"
  // - previous graph data, 2 - two steps "ago". I.e. it's number of graph
  // points from the right graph edge.
  float GetUnscaledValueAt(size_t index) const;

  // Returns true if |data_| is populated at the given index.
  // |index| is always interpreted as "negative", i.e. "0" - current data, "1"
  // - previous graph data, 2 - two steps ago. I.e. it's number of graph
  // points from the right graph edge.
  bool IsFilledIndex(size_t index) const;

#if !defined(NDEBUG)
  // Returns string representation os this object for debug.
  std::string DebugDump(const std::string& name) const;
#endif

 private:
  const Baseline baseline_;
  const Fill fill_;
  const SkColor color_;

  // Result of last Layout() call.
  gfx::Rect graph_bounds_;

  // Paths are measured from the top left corner.
  // Partial graph is assumed to be right-justified.
  // For BASELINE_BOTTOM |top_path_| has y values that are less than
  // |bottom_path_|. (And opposite for the BASELINE_TOP.)
  // Paths are calculated by Layout() from the |data_|.
  std::vector<SkPoint> top_path_;
  std::vector<SkPoint> bottom_path_;

  Data data_;
  Data unscaled_data_;
};

}  // namespace hud_display
}  // namespace ash

#endif  // ASH_HUD_DISPLAY_GRAPH_H_
