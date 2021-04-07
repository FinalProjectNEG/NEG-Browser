// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_SHARESHEET_SHARESHEET_SERVICE_FACTORY_H_
#define CHROME_BROWSER_SHARESHEET_SHARESHEET_SERVICE_FACTORY_H_

#include "base/memory/singleton.h"
#include "components/keyed_service/content/browser_context_keyed_service_factory.h"

class Profile;

namespace sharesheet {

class SharesheetService;

// Singleton that owns all SharesheetServices and associates them with Profile.
class SharesheetServiceFactory : public BrowserContextKeyedServiceFactory {
 public:
  static SharesheetService* GetForProfile(Profile* profile);

  static SharesheetServiceFactory* GetInstance();

  SharesheetServiceFactory(const SharesheetServiceFactory&) = delete;
  SharesheetServiceFactory& operator=(const SharesheetServiceFactory&) = delete;

 private:
  friend struct base::DefaultSingletonTraits<SharesheetServiceFactory>;

  SharesheetServiceFactory();
  ~SharesheetServiceFactory() override;

  // BrowserContextKeyedServiceFactory overrides.
  KeyedService* BuildServiceInstanceFor(
      content::BrowserContext* context) const override;
  content::BrowserContext* GetBrowserContextToUse(
      content::BrowserContext* context) const override;
  bool ServiceIsCreatedWithBrowserContext() const override;
};

}  // namespace sharesheet

#endif  // CHROME_BROWSER_SHARESHEET_SHARESHEET_SERVICE_FACTORY_H_
