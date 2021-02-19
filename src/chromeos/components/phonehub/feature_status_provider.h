// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROMEOS_COMPONENTS_PHONEHUB_FEATURE_STATUS_PROVIDER_H_
#define CHROMEOS_COMPONENTS_PHONEHUB_FEATURE_STATUS_PROVIDER_H_

#include "base/observer_list.h"
#include "base/observer_list_types.h"
#include "chromeos/components/phonehub/feature_status.h"

namespace chromeos {
namespace phonehub {

// Provides the current status of Phone Hub and notifies observers when the
// status changes.
class FeatureStatusProvider {
 public:
  class Observer : public base::CheckedObserver {
   public:
    ~Observer() override = default;

    // Called when the status has changed; use GetStatus() for the new status.
    virtual void OnFeatureStatusChanged() = 0;
  };

  FeatureStatusProvider(const FeatureStatusProvider&) = delete;
  FeatureStatusProvider& operator=(const FeatureStatusProvider&) = delete;
  virtual ~FeatureStatusProvider();

  virtual FeatureStatus GetStatus() const = 0;

  void AddObserver(Observer* observer);
  void RemoveObserver(Observer* observer);

 protected:
  FeatureStatusProvider();

  void NotifyStatusChanged();

 private:
  base::ObserverList<Observer> observer_list_;
};

}  // namespace phonehub
}  // namespace chromeos

#endif  // CHROMEOS_COMPONENTS_PHONEHUB_FEATURE_STATUS_PROVIDER_H_
