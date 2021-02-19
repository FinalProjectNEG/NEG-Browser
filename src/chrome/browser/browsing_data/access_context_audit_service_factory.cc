// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/browsing_data/access_context_audit_service_factory.h"

#include "base/memory/singleton.h"
#include "chrome/browser/browsing_data/access_context_audit_service.h"
#include "chrome/browser/content_settings/host_content_settings_map_factory.h"
#include "chrome/browser/history/history_service_factory.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/common/chrome_features.h"
#include "components/keyed_service/content/browser_context_dependency_manager.h"
#include "content/public/browser/browser_context.h"
#include "content/public/browser/storage_partition.h"

AccessContextAuditServiceFactory::AccessContextAuditServiceFactory()
    : BrowserContextKeyedServiceFactory(
          "AccessContextAuditService",
          BrowserContextDependencyManager::GetInstance()) {
  DependsOn(HostContentSettingsMapFactory::GetInstance());
  DependsOn(HistoryServiceFactory::GetInstance());
}

AccessContextAuditServiceFactory*
AccessContextAuditServiceFactory::GetInstance() {
  return base::Singleton<AccessContextAuditServiceFactory>::get();
}

AccessContextAuditService* AccessContextAuditServiceFactory::GetForProfile(
    Profile* profile) {
  return static_cast<AccessContextAuditService*>(
      GetInstance()->GetServiceForBrowserContext(profile, true));
}

KeyedService* AccessContextAuditServiceFactory::BuildServiceInstanceFor(
    content::BrowserContext* context) const {
  if (context->IsOffTheRecord() ||
      !base::FeatureList::IsEnabled(
          features::kClientStorageAccessContextAuditing))
    return nullptr;

  auto* profile = static_cast<Profile*>(context);

  // The service implementation will persist session cookies until next startup.
  // It is only used with regular profiles, which always persist session
  // cookies.
  DCHECK(profile->ShouldPersistSessionCookies());

  std::unique_ptr<AccessContextAuditService> context_audit_service(
      new AccessContextAuditService(profile));
  if (!context_audit_service->Init(
          context->GetPath(),
          content::BrowserContext::GetDefaultStoragePartition(context)
              ->GetCookieManagerForBrowserProcess(),
          HistoryServiceFactory::GetForProfile(
              profile, ServiceAccessType::EXPLICIT_ACCESS),
          content::BrowserContext::GetDefaultStoragePartition(context))) {
    return nullptr;
  }

  return context_audit_service.release();
}

bool AccessContextAuditServiceFactory::ServiceIsCreatedWithBrowserContext()
    const {
  return true;
}

bool AccessContextAuditServiceFactory::ServiceIsNULLWhileTesting() const {
  // Service relies on cookie manager associated with the profile storage
  // partition which may not be present in tests.
  return true;
}
