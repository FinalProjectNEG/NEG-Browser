// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_CHROMEOS_REMOTE_APPS_REMOTE_APPS_MANAGER_FACTORY_H_
#define CHROME_BROWSER_CHROMEOS_REMOTE_APPS_REMOTE_APPS_MANAGER_FACTORY_H_

#include "base/no_destructor.h"
#include "chrome/browser/chromeos/remote_apps/remote_apps_manager.h"
#include "components/keyed_service/content/browser_context_keyed_service_factory.h"

class KeyedService;
class Profile;

namespace content {
class BrowserContext;
}  // namespace content

namespace chromeos {

// Singleton that creates |RemoteAppsManager|s and associates them with a
// |Profile|.
class RemoteAppsManagerFactory : public BrowserContextKeyedServiceFactory {
 public:
  static RemoteAppsManager* GetForProfile(Profile* profile);

  static RemoteAppsManagerFactory* GetInstance();

 private:
  friend base::NoDestructor<RemoteAppsManagerFactory>;

  RemoteAppsManagerFactory();
  RemoteAppsManagerFactory(const RemoteAppsManagerFactory&) = delete;
  RemoteAppsManagerFactory& operator=(const RemoteAppsManagerFactory&) = delete;
  ~RemoteAppsManagerFactory() override;

  // BrowserContextKeyedServiceFactory:
  KeyedService* BuildServiceInstanceFor(
      content::BrowserContext* context) const override;
  content::BrowserContext* GetBrowserContextToUse(
      content::BrowserContext* context) const override;
  bool ServiceIsCreatedWithBrowserContext() const override;
};

}  // namespace chromeos

#endif  // CHROME_BROWSER_CHROMEOS_REMOTE_APPS_REMOTE_APPS_MANAGER_FACTORY_H_
