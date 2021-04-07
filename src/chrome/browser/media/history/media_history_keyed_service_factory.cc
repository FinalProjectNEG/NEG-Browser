// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/media/history/media_history_keyed_service_factory.h"

#include "chrome/browser/history/history_service_factory.h"
#include "chrome/browser/media/history/media_history_keyed_service.h"
#include "chrome/browser/profiles/profile.h"
#include "components/keyed_service/content/browser_context_dependency_manager.h"
#include "content/public/browser/browser_context.h"

namespace media_history {

// static
MediaHistoryKeyedService* MediaHistoryKeyedServiceFactory::GetForProfile(
    Profile* profile) {
  return static_cast<MediaHistoryKeyedService*>(
      GetInstance()->GetServiceForBrowserContext(profile, true));
}

// static
MediaHistoryKeyedServiceFactory*
MediaHistoryKeyedServiceFactory::GetInstance() {
  return base::Singleton<MediaHistoryKeyedServiceFactory>::get();
}

MediaHistoryKeyedServiceFactory::MediaHistoryKeyedServiceFactory()
    : BrowserContextKeyedServiceFactory(
          "MediaHistoryKeyedService",
          BrowserContextDependencyManager::GetInstance()) {
  DependsOn(HistoryServiceFactory::GetInstance());
}

MediaHistoryKeyedServiceFactory::~MediaHistoryKeyedServiceFactory() = default;

bool MediaHistoryKeyedServiceFactory::ServiceIsCreatedWithBrowserContext()
    const {
  return true;
}

KeyedService* MediaHistoryKeyedServiceFactory::BuildServiceInstanceFor(
    content::BrowserContext* context) const {
  return new MediaHistoryKeyedService(Profile::FromBrowserContext(context));
}

content::BrowserContext*
MediaHistoryKeyedServiceFactory::GetBrowserContextToUse(
    content::BrowserContext* context) const {
  // Enable incognito profiles.
  return context;
}

}  // namespace media_history
