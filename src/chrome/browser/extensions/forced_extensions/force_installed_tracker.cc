// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/extensions/forced_extensions/force_installed_tracker.h"

#include "base/bind.h"
#include "base/values.h"
#include "chrome/browser/extensions/extension_management_constants.h"
#include "chrome/browser/extensions/external_provider_impl.h"
#include "chrome/browser/extensions/forced_extensions/install_stage_tracker.h"
#include "chrome/browser/policy/profile_policy_connector.h"
#include "chrome/browser/profiles/profile.h"
#include "components/prefs/pref_service.h"
#include "extensions/browser/install/crx_install_error.h"
#include "extensions/browser/pref_names.h"
#include "extensions/common/extension_urls.h"

#if defined(OS_CHROMEOS)
#include "components/arc/arc_prefs.h"
#endif  // defined(OS_CHROMEOS)

namespace extensions {

ForceInstalledTracker::ForceInstalledTracker(ExtensionRegistry* registry,
                                             Profile* profile)
    : extension_management_(
          ExtensionManagementFactory::GetForBrowserContext(profile)),
      registry_(registry),
      profile_(profile),
      pref_service_(profile->GetPrefs()) {
  // Load immediately if PolicyService is ready, or wait for it to finish
  // initializing first.
  if (policy_service()->IsInitializationComplete(policy::POLICY_DOMAIN_CHROME))
    OnForcedExtensionsPrefReady();
  else
    policy_service()->AddObserver(policy::POLICY_DOMAIN_CHROME, this);
}

ForceInstalledTracker::~ForceInstalledTracker() {
  policy_service()->RemoveObserver(policy::POLICY_DOMAIN_CHROME, this);
}

void ForceInstalledTracker::UpdateCounters(ExtensionStatus status, int delta) {
  switch (status) {
    case ExtensionStatus::PENDING:
      load_pending_count_ += delta;
      FALLTHROUGH;
    case ExtensionStatus::LOADED:
      ready_pending_count_ += delta;
      break;
    case ExtensionStatus::READY:
    case ExtensionStatus::FAILED:
      break;
  }
}

void ForceInstalledTracker::AddExtensionInfo(const ExtensionId& extension_id,
                                             ExtensionStatus status,
                                             bool is_from_store) {
  auto result =
      extensions_.emplace(extension_id, ExtensionInfo{status, is_from_store});
  DCHECK(result.second);
  UpdateCounters(result.first->second.status, +1);
}

void ForceInstalledTracker::ChangeExtensionStatus(
    const ExtensionId& extension_id,
    ExtensionStatus status) {
  DCHECK_GE(status_, kWaitingForExtensionLoads);
  auto item = extensions_.find(extension_id);
  if (item == extensions_.end())
    return;
  UpdateCounters(item->second.status, -1);
  item->second.status = status;
  UpdateCounters(item->second.status, +1);
}

void ForceInstalledTracker::OnPolicyUpdated(const policy::PolicyNamespace& ns,
                                            const policy::PolicyMap& previous,
                                            const policy::PolicyMap& current) {}

void ForceInstalledTracker::OnPolicyServiceInitialized(
    policy::PolicyDomain domain) {
  DCHECK_EQ(domain, policy::POLICY_DOMAIN_CHROME);
  DCHECK_EQ(status_, kWaitingForPolicyService);
  policy_service()->RemoveObserver(policy::POLICY_DOMAIN_CHROME, this);
  OnForcedExtensionsPrefReady();
}

void ForceInstalledTracker::OnForcedExtensionsPrefReady() {
  DCHECK(
      policy_service()->IsInitializationComplete(policy::POLICY_DOMAIN_CHROME));
  DCHECK_EQ(status_, kWaitingForPolicyService);

  // Listen for extension loads and install failures.
  status_ = kWaitingForExtensionLoads;
  registry_observer_.Add(registry_);
  collector_observer_.Add(InstallStageTracker::Get(profile_));

  const base::DictionaryValue* value =
      pref_service_->GetDictionary(pref_names::kInstallForceList);
  if (value) {
    // Add each extension to |extensions_|.
    for (const auto& entry : *value) {
      const ExtensionId& extension_id = entry.first;
      std::string* update_url = nullptr;
      if (entry.second->is_dict()) {
        update_url = entry.second->FindStringKey(
            ExternalProviderImpl::kExternalUpdateUrl);
      }
      bool is_from_store =
          update_url && *update_url == extension_urls::kChromeWebstoreUpdateURL;

      ExtensionStatus status = ExtensionStatus::PENDING;
      if (registry_->enabled_extensions().Contains(extension_id)) {
        status = registry_->ready_extensions().Contains(extension_id)
                     ? ExtensionStatus::READY
                     : ExtensionStatus::LOADED;
      }
      AddExtensionInfo(extension_id, status, is_from_store);
    }
  }

  // Run observers if there are no pending installs.
  MaybeNotifyObservers();
}

void ForceInstalledTracker::OnShutdown(ExtensionRegistry*) {
  registry_observer_.RemoveAll();
}

void ForceInstalledTracker::AddObserver(Observer* obs) {
  observers_.AddObserver(obs);
}

void ForceInstalledTracker::RemoveObserver(Observer* obs) {
  observers_.RemoveObserver(obs);
}

void ForceInstalledTracker::OnExtensionLoaded(
    content::BrowserContext* browser_context,
    const Extension* extension) {
  ChangeExtensionStatus(extension->id(), ExtensionStatus::LOADED);
  MaybeNotifyObservers();
}

void ForceInstalledTracker::OnExtensionReady(
    content::BrowserContext* browser_context,
    const Extension* extension) {
  ChangeExtensionStatus(extension->id(), ExtensionStatus::READY);
  MaybeNotifyObservers();
}

void ForceInstalledTracker::OnExtensionInstallationFailed(
    const ExtensionId& extension_id,
    InstallStageTracker::FailureReason reason) {
  auto item = extensions_.find(extension_id);
  // If the extension is loaded, ignore the failure.
  if (item == extensions_.end() ||
      item->second.status == ExtensionStatus::LOADED ||
      item->second.status == ExtensionStatus::READY)
    return;
  ChangeExtensionStatus(extension_id, ExtensionStatus::FAILED);
  MaybeNotifyObservers();
}

bool ForceInstalledTracker::IsDoneLoading() const {
  return status_ == kWaitingForExtensionReady || status_ == kComplete;
}

void ForceInstalledTracker::OnExtensionDownloadCacheStatusRetrieved(
    const ExtensionId& id,
    ExtensionDownloaderDelegate::CacheStatus cache_status) {
  // Report cache status only for forced installed extension.
  if (extensions_.find(id) != extensions_.end()) {
    for (auto& obs : observers_)
      obs.OnExtensionDownloadCacheStatusRetrieved(id, cache_status);
  }
}

bool ForceInstalledTracker::IsReady() const {
  return status_ == kComplete;
}

bool ForceInstalledTracker::IsMisconfiguration(
    const InstallStageTracker::InstallationData& installation_data,
    const ExtensionId& id) const {
  if (installation_data.install_error_detail) {
    CrxInstallErrorDetail detail =
        installation_data.install_error_detail.value();
    if (detail == CrxInstallErrorDetail::KIOSK_MODE_ONLY)
      return true;

    if (installation_data.extension_type &&
        detail == CrxInstallErrorDetail::DISALLOWED_BY_POLICY &&
        !extension_management_->IsAllowedManifestType(
            installation_data.extension_type.value(), id)) {
      return true;
    }
  }

#if defined(OS_CHROMEOS)
  // REPLACED_BY_ARC_APP error is a misconfiguration if ARC++ is enabled for
  // the device.
  if (profile_->GetPrefs()->IsManagedPreference(arc::prefs::kArcEnabled) &&
      profile_->GetPrefs()->GetBoolean(arc::prefs::kArcEnabled) &&
      installation_data.failure_reason ==
          InstallStageTracker::FailureReason::REPLACED_BY_ARC_APP) {
    return true;
  }
#endif  // defined(OS_CHROMEOS)

  if (installation_data.failure_reason ==
      InstallStageTracker::FailureReason::NOT_PERFORMING_NEW_INSTALL) {
    return true;
  }
  if (installation_data.failure_reason ==
      InstallStageTracker::FailureReason::CRX_FETCH_URL_EMPTY) {
    DCHECK(installation_data.no_updates_info);
    if (installation_data.no_updates_info.value() ==
        InstallStageTracker::NoUpdatesInfo::kEmpty) {
      return true;
    }
  }

  if (installation_data.manifest_invalid_error ==
          ManifestInvalidError::BAD_APP_STATUS &&
      installation_data.app_status_error ==
          InstallStageTracker::AppStatusError::kErrorUnknownApplication) {
    return true;
  }

  return false;
}

policy::PolicyService* ForceInstalledTracker::policy_service() {
  return profile_->GetProfilePolicyConnector()->policy_service();
}

void ForceInstalledTracker::MaybeNotifyObservers() {
  DCHECK_GE(status_, kWaitingForExtensionLoads);
  if (status_ == kWaitingForExtensionLoads && load_pending_count_ == 0) {
    for (auto& obs : observers_)
      obs.OnForceInstalledExtensionsLoaded();
    status_ = kWaitingForExtensionReady;
  }
  if (status_ == kWaitingForExtensionReady && ready_pending_count_ == 0) {
    for (auto& obs : observers_)
      obs.OnForceInstalledExtensionsReady();
    status_ = kComplete;
    registry_observer_.RemoveAll();
    collector_observer_.RemoveAll();
    InstallStageTracker::Get(profile_)->Clear();
  }
}

}  //  namespace extensions
