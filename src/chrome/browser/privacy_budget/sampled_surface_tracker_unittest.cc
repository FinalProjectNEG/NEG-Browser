// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/privacy_budget/sampled_surface_tracker.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/privacy_budget/identifiable_surface.h"

namespace {
uint64_t metric(int i) {
  return blink::IdentifiableSurface::FromTypeAndToken(
             blink::IdentifiableSurface::Type::kWebFeature, i)
      .ToUkmMetricHash();
}
}  // namespace

TEST(SampledSurfaceTrackerTest, Dedup) {
  SampledSurfaceTracker t;
  EXPECT_TRUE(t.ShouldRecord(0, metric(1)));
  EXPECT_FALSE(t.ShouldRecord(0, metric(1)));
  EXPECT_TRUE(t.ShouldRecord(1, metric(1)));
}

TEST(SampledSurfaceTrackerTest, SizeLimit) {
  SampledSurfaceTracker t;
  for (uint64_t i = 0; i < SampledSurfaceTracker::kMaxTrackedSurfaces; i++) {
    EXPECT_TRUE(t.ShouldRecord(0, metric(i))) << ": 0," << i;
  }
  // Now the tracker should be full, but we will still allow new sources.
  for (uint64_t i = 0; i < SampledSurfaceTracker::kMaxTrackedSurfaces; i++) {
    EXPECT_FALSE(t.ShouldRecord(0, metric(i))) << ": 0," << i;
    EXPECT_TRUE(t.ShouldRecord(1, metric(i))) << ": 1," << i;
  }

  // Add an extra one. This should bump one of the surfaces out.
  t.ShouldRecord(0, SampledSurfaceTracker::kMaxTrackedSurfaces + 1);

  // We expect only kMaxTrackedSurfaces to return true for a new surface.
  unsigned num_true = 0;
  for (uint64_t i = 0; i < SampledSurfaceTracker::kMaxTrackedSurfaces + 1;
       i++) {
    if (t.ShouldRecord(2, metric(i)))
      num_true++;
  }
  EXPECT_EQ(SampledSurfaceTracker::kMaxTrackedSurfaces, num_true);
}

TEST(SampledSurfaceTrackerTest, Reset) {
  SampledSurfaceTracker t;
  EXPECT_TRUE(t.ShouldRecord(0, metric(0))) << ": 0,0";
  EXPECT_FALSE(t.ShouldRecord(0, metric(0))) << ": 0,0";
  t.Reset();
  EXPECT_TRUE(t.ShouldRecord(0, metric(0))) << ": 0,0";
}

TEST(SampledSurfaceTrackerTest, InvalidMetric) {
  SampledSurfaceTracker t;
  EXPECT_FALSE(t.ShouldRecord(
      0, blink::IdentifiableSurface::FromTypeAndToken(
             blink::IdentifiableSurface::Type::kReservedInternal, 1)
             .ToUkmMetricHash()));
}
