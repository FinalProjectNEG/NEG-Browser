// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ios/chrome/browser/policy_url_blocking/policy_url_blocking_service.h"
#include <iostream>
#include "components/keyed_service/ios/browser_state_dependency_manager.h"
#include "ios/chrome/browser/application_context.h"
#include "ios/chrome/browser/browser_state/chrome_browser_state.h"
#include "ios/web/public/browser_state.h"

PolicyBlocklistService::PolicyBlocklistService(
    web::BrowserState* browser_state,
    std::unique_ptr<policy::URLBlocklistManager> url_blocklist_manager)
    : url_blocklist_manager_(std::move(url_blocklist_manager)) {}

PolicyBlocklistService::~PolicyBlocklistService() = default;

policy::URLBlocklist::URLBlocklistState
PolicyBlocklistService::GetURLBlocklistState(const GURL& url) const {
  std::cout<<"\nNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN\n";
  return url_blocklist_manager_->GetURLBlocklistState(url);
}

// static
PolicyBlocklistServiceFactory* PolicyBlocklistServiceFactory::GetInstance() {
  static base::NoDestructor<PolicyBlocklistServiceFactory> instance;
  return instance.get();
}

// static
PolicyBlocklistService* PolicyBlocklistServiceFactory::GetForBrowserState(
    web::BrowserState* browser_state) {
  return static_cast<PolicyBlocklistService*>(
      GetInstance()->GetServiceForBrowserState(browser_state, /*create=*/true));
}

PolicyBlocklistServiceFactory::PolicyBlocklistServiceFactory()
    : BrowserStateKeyedServiceFactory(
          "PolicyBlocklist",
          BrowserStateDependencyManager::GetInstance()) {}

PolicyBlocklistServiceFactory::~PolicyBlocklistServiceFactory() = default;

std::unique_ptr<KeyedService>
PolicyBlocklistServiceFactory::BuildServiceInstanceFor(
    web::BrowserState* browser_state) const {
  PrefService* prefs =
      ChromeBrowserState::FromBrowserState(browser_state)->GetPrefs();
  auto url_blocklist_manager =
      std::make_unique<policy::URLBlocklistManager>(prefs);
  return std::make_unique<PolicyBlocklistService>(
      browser_state, std::move(url_blocklist_manager));
}

web::BrowserState* PolicyBlocklistServiceFactory::GetBrowserStateToUse(
    web::BrowserState* browser_state) const {
  // Create the service for both normal and incognito browser states.
  return browser_state;
}
