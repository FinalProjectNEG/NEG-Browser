// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_SUBRESOURCE_FILTER_SUBRESOURCE_FILTER_CONTENT_SETTINGS_MANAGER_H_
#define CHROME_BROWSER_SUBRESOURCE_FILTER_SUBRESOURCE_FILTER_CONTENT_SETTINGS_MANAGER_H_

#include <memory>
#include <utility>

#include "base/macros.h"
#include "base/scoped_observer.h"
#include "base/time/clock.h"
#include "base/time/time.h"
#include "components/content_settings/core/common/content_settings.h"
#include "components/history/core/browser/history_service.h"
#include "components/history/core/browser/history_service_observer.h"

class GURL;
class HostContentSettingsMap;
class Profile;

namespace base {
class DictionaryValue;
}  // namespace base

// This class contains helpers to get/set content and website settings related
// to subresource filtering.
//
// Site metadata is stored in two formats as a base::DictionaryValue:
// -  V1 (or legacy) metadata, which uses the presence of metadata to indicate
//    activation due to safe browsing and may store additional data for
//    the time since UI was shown, see OnDidShowUI. The absence of metadata
//    indicates no activation.
//    TODO(justinmiron): All V1 metadata will be updated to V2 when it is
//    processed, but we should ideally migrate it all at some point to remove
//    this case.
//
// -  V2 metadata, which explicitly stores the activation status in a key
//    within the metadata dict. This metadata, by default, expires after 1
//    week. However, when metadata is set by an ads intervention, and we
//    and ads interventions are not blocking ads (no activation), the
//    expiration time is explicitly set to match the metadata expiry key in the
//    metadata dict. Additional data may be persisted but will be deleted
//    if there is no activation and the metadata expiry key is not set.
//
// Data stored in the metadata for a url:
// - kInfobarLastShownTimeKey (V1/V2): The last time the info bar was shown for
//   the smart UI.
// - kActivatedKey (V2): The current activation status of the url.
// - kNonRenewingExpiryTime (V2): The time that this url's
//   metadata will expire at and be cleared from the website settings.
//   Note, if this is set, there is no code path that should be able to extend
//   the expiry time. This is a "non-renewable" expiry.
//   TODO(https://crbug.com/1113967): This ensures that even safe browsing
//   activation is not persisted for the full expiration if it comes after an
//   ads intervention. This is non-ideal and this behavior should be removed
//   when metrics collection is finished, in M88.
//
// TODO(crbug.com/706061): Once observing changes to content settings is robust
// enough for metrics collection, should collect metrics here too, using a
// content_settings::Observer. Generally speaking, we want a system where we can
// easily log metrics if the content setting has changed meaningfully from it's
// previous value.
class SubresourceFilterContentSettingsManager
    : public history::HistoryServiceObserver {
 public:
  explicit SubresourceFilterContentSettingsManager(Profile* profile);
  ~SubresourceFilterContentSettingsManager() override;

  ContentSetting GetSitePermission(const GURL& url) const;

  // Only called via direct user action on via the subresource filter UI. Sets
  // the content setting to turn off the subresource filter.
  void AllowlistSite(const GURL& url);

  // Public for testing.
  std::unique_ptr<base::DictionaryValue> GetSiteMetadata(const GURL& url) const;

  // Specific logic for more intelligent UI.
  void OnDidShowUI(const GURL& url);
  bool ShouldShowUIForSite(const GURL& url) const;
  bool should_use_smart_ui() const { return should_use_smart_ui_; }
  void set_should_use_smart_ui_for_testing(bool should_use_smart_ui) {
    should_use_smart_ui_ = should_use_smart_ui;
  }

  // Enumerates the source of setting metadata in
  // SetSiteMetadataBasedOnActivation.
  enum class ActivationSource {
    // The safe browsing component has activated on the site as it
    // is on one of the safe browsing lists.
    kSafeBrowsing,

    // An ads intervention has been triggered for the site. Whether
    // we activate on the site depends on if ad blocking for ads
    // intervention is currently enabled.
    kAdsIntervention,
  };

  // Updates the site metadata based on the state of subresource filter
  // activation. See class comment for information on metadata data model.
  void SetSiteMetadataBasedOnActivation(
      const GURL& url,
      bool is_activated,
      ActivationSource activation_source,
      std::unique_ptr<base::DictionaryValue> additional_metadata = nullptr);

  // Returns the activation status based on the |url|'s site metadata. See
  // class comment for information on the metadata data model.
  bool GetSiteActivationFromMetadata(const GURL& url);

  void set_clock_for_testing(std::unique_ptr<base::Clock> tick_clock) {
    clock_ = std::move(tick_clock);
  }

  // Time before showing the UI again on a domain.
  // TODO(csharrison): Consider setting this via a finch param.
  static constexpr base::TimeDelta kDelayBeforeShowingInfobarAgain =
      base::TimeDelta::FromHours(24);

  // Maximum duration to persist metadata for.
  static constexpr base::TimeDelta kMaxPersistMetadataDuration =
      base::TimeDelta::FromDays(7);

  // Overwrites existing site metadata for testing.
  void SetSiteMetadataForTesting(const GURL& url,
                                 std::unique_ptr<base::DictionaryValue> dict);

 private:
  // history::HistoryServiceObserver:
  void OnURLsDeleted(history::HistoryService* history_service,
                     const history::DeletionInfo& deletion_info) override;

  void SetSiteMetadata(const GURL& url,
                       std::unique_ptr<base::DictionaryValue> dict);

  std::unique_ptr<base::DictionaryValue> CreateMetadataDictWithActivation(
      bool is_activated);

  // Whether the site metadata stored in |dict| is being persisted with an
  // expiry time set by an ads intervention.
  bool ShouldDeleteDataWithNoActivation(base::DictionaryValue* dict,
                                        ActivationSource activation_source);

  ScopedObserver<history::HistoryService, history::HistoryServiceObserver>
      history_observer_{this};

  HostContentSettingsMap* settings_map_;

  // A clock is injected into this class so tests can set arbitrary timestamps
  // in website settings.
  std::unique_ptr<base::Clock> clock_;

  bool should_use_smart_ui_ = false;

  DISALLOW_COPY_AND_ASSIGN(SubresourceFilterContentSettingsManager);
};

#endif  // CHROME_BROWSER_SUBRESOURCE_FILTER_SUBRESOURCE_FILTER_CONTENT_SETTINGS_MANAGER_H_
