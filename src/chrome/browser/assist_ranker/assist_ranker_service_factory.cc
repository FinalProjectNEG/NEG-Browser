// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/assist_ranker/assist_ranker_service_factory.h"

#include "chrome/browser/browser_process.h"
#include "chrome/browser/net/system_network_context_manager.h"
#include "chrome/browser/profiles/incognito_helpers.h"
#include "components/assist_ranker/assist_ranker_service_impl.h"
#include "components/keyed_service/content/browser_context_dependency_manager.h"
#include "components/keyed_service/core/keyed_service.h"
#include "content/public/browser/browser_context.h"
#include "services/network/public/cpp/shared_url_loader_factory.h"

namespace assist_ranker {

// static
AssistRankerServiceFactory* AssistRankerServiceFactory::GetInstance() {
  return base::Singleton<AssistRankerServiceFactory>::get();
}

// static
AssistRankerService* AssistRankerServiceFactory::GetForBrowserContext(
    content::BrowserContext* browser_context) {
  return static_cast<AssistRankerService*>(
      GetInstance()->GetServiceForBrowserContext(browser_context, true));
}

AssistRankerServiceFactory::AssistRankerServiceFactory()
    : BrowserContextKeyedServiceFactory(
          "AssistRankerService",
          BrowserContextDependencyManager::GetInstance()) {}

AssistRankerServiceFactory::~AssistRankerServiceFactory() {}

KeyedService* AssistRankerServiceFactory::BuildServiceInstanceFor(
    content::BrowserContext* browser_context) const {
  return new AssistRankerServiceImpl(
      browser_context->GetPath(),
      g_browser_process->system_network_context_manager()
          ->GetSharedURLLoaderFactory());
}

content::BrowserContext* AssistRankerServiceFactory::GetBrowserContextToUse(
    content::BrowserContext* context) const {
  return chrome::GetBrowserContextRedirectedInIncognito(context);
}

}  // namespace assist_ranker
