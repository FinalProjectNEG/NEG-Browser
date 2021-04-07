// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/common/privacy_budget/privacy_budget_settings_provider.h"

#include <memory>

#include "base/stl_util.h"
#include "chrome/common/privacy_budget/field_trial_param_conversions.h"
#include "chrome/common/privacy_budget/privacy_budget_features.h"
#include "third_party/blink/public/common/privacy_budget/identifiable_surface.h"

PrivacyBudgetSettingsProvider::PrivacyBudgetSettingsProvider()
    : blocked_surfaces_(
          DecodeIdentifiabilityFieldTrialParam<IdentifiableSurfaceSet>(
              features::kIdentifiabilityStudyBlockedMetrics.Get())),
      blocked_types_(
          DecodeIdentifiabilityFieldTrialParam<IdentifiableSurfaceTypeSet>(
              features::kIdentifiabilityStudyBlockedTypes.Get())),

      // In practice there's really no point in enabling the feature with a max
      // active surface count of 0.
      enabled_(base::FeatureList::IsEnabled(features::kIdentifiabilityStudy) &&
               features::kIdentifiabilityStudySurfaceSelectionRate.Get() > 0) {}

PrivacyBudgetSettingsProvider::PrivacyBudgetSettingsProvider(
    const PrivacyBudgetSettingsProvider&) = default;
PrivacyBudgetSettingsProvider::PrivacyBudgetSettingsProvider(
    PrivacyBudgetSettingsProvider&&) = default;
PrivacyBudgetSettingsProvider::~PrivacyBudgetSettingsProvider() = default;

bool PrivacyBudgetSettingsProvider::IsActive() const {
  return enabled_;
}

bool PrivacyBudgetSettingsProvider::IsAnyTypeOrSurfaceBlocked() const {
  return !blocked_surfaces_.empty() || !blocked_types_.empty();
}

bool PrivacyBudgetSettingsProvider::IsSurfaceAllowed(
    blink::IdentifiableSurface surface) const {
  return !base::Contains(blocked_surfaces_, surface) &&
         IsTypeAllowed(surface.GetType());
}

bool PrivacyBudgetSettingsProvider::IsTypeAllowed(
    blink::IdentifiableSurface::Type type) const {
  return !base::Contains(blocked_types_, type);
}
