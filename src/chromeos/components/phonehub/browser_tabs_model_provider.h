// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROMEOS_COMPONENTS_PHONEHUB_BROWSER_TABS_MODEL_PROVIDER_H_
#define CHROMEOS_COMPONENTS_PHONEHUB_BROWSER_TABS_MODEL_PROVIDER_H_

#include <ostream>

#include "base/observer_list.h"
#include "base/observer_list_types.h"
#include "chromeos/components/phonehub/browser_tabs_model.h"

namespace chromeos {
namespace phonehub {

// Responsible for providing BrowserTabsModel information to observers.
// Gets the browser tab model info by finding a SyncedSession (provided by
// the SessionService) with a |session_name| that matches the |pii_free_name| of
// the phone provided by a MultiDeviceSetupClient. If sync is enabled, the class
// uses a BrowserTabsMetadataFetcher to actually fetch the browser tab metadata
// once it finds the correct SyncedSession.
class BrowserTabsModelProvider {
 public:
  class Observer : public base::CheckedObserver {
   public:
    ~Observer() override = default;

    virtual void OnBrowserTabsUpdated(
        bool is_sync_enabled,
        const std::vector<BrowserTabsModel::BrowserTabMetadata>&
            browser_tabs_metadata) = 0;
  };

  BrowserTabsModelProvider(const BrowserTabsModelProvider&) = delete;
  BrowserTabsModelProvider* operator=(const BrowserTabsModelProvider&) = delete;
  virtual ~BrowserTabsModelProvider();

  void AddObserver(Observer* observer);
  void RemoveObserver(Observer* observer);

 protected:
  BrowserTabsModelProvider();

  void NotifyBrowserTabsUpdated(
      bool is_sync_enabled,
      const std::vector<BrowserTabsModel::BrowserTabMetadata>
          browser_tabs_metadata);

 private:
  base::ObserverList<Observer> observer_list_;
};

}  // namespace phonehub
}  // namespace chromeos

#endif  // CHROMEOS_COMPONENTS_PHONEHUB_BROWSER_TABS_MODEL_PROVIDER_H_
