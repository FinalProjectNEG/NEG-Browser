// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chromeos/components/phonehub/fake_feature_status_provider.h"

namespace chromeos {
namespace phonehub {

FakeFeatureStatusProvider::FakeFeatureStatusProvider()
    : FakeFeatureStatusProvider(FeatureStatus::kEnabledAndConnected) {}

FakeFeatureStatusProvider::FakeFeatureStatusProvider(
    FeatureStatus initial_status)
    : status_(initial_status) {}

FakeFeatureStatusProvider::~FakeFeatureStatusProvider() = default;

void FakeFeatureStatusProvider::SetStatus(FeatureStatus status) {
  if (status == status_)
    return;

  status_ = status;
  NotifyStatusChanged();
}

FeatureStatus FakeFeatureStatusProvider::GetStatus() const {
  return status_;
}

}  // namespace phonehub
}  // namespace chromeos
