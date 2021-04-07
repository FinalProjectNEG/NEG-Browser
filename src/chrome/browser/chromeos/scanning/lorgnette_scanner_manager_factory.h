// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_CHROMEOS_SCANNING_LORGNETTE_SCANNER_MANAGER_FACTORY_H_
#define CHROME_BROWSER_CHROMEOS_SCANNING_LORGNETTE_SCANNER_MANAGER_FACTORY_H_

#include "components/keyed_service/content/browser_context_keyed_service_factory.h"

namespace base {
template <typename T>
struct DefaultSingletonTraits;
}

namespace content {
class BrowserContext;
}

namespace chromeos {

class LorgnetteScannerManager;

// Factory for LorgnetteScannerManager.
class LorgnetteScannerManagerFactory
    : public BrowserContextKeyedServiceFactory {
 public:
  static LorgnetteScannerManager* GetForBrowserContext(
      content::BrowserContext* context);
  static LorgnetteScannerManagerFactory* GetInstance();

 private:
  friend struct base::DefaultSingletonTraits<LorgnetteScannerManagerFactory>;

  LorgnetteScannerManagerFactory();
  ~LorgnetteScannerManagerFactory() override;

  LorgnetteScannerManagerFactory(const LorgnetteScannerManagerFactory&) =
      delete;
  LorgnetteScannerManagerFactory& operator=(
      const LorgnetteScannerManagerFactory&) = delete;

  // BrowserContextKeyedServiceFactory:
  KeyedService* BuildServiceInstanceFor(
      content::BrowserContext* context) const override;
  bool ServiceIsCreatedWithBrowserContext() const override;
  bool ServiceIsNULLWhileTesting() const override;
};

}  // namespace chromeos

#endif  // CHROME_BROWSER_CHROMEOS_SCANNING_LORGNETTE_SCANNER_MANAGER_FACTORY_H_
