// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/chromeos/platform_keys/key_permissions/mock_key_permissions_service.h"

#include <memory>

#include "content/public/browser/browser_context.h"

namespace chromeos {
namespace platform_keys {

MockKeyPermissionsService::MockKeyPermissionsService() = default;
MockKeyPermissionsService::~MockKeyPermissionsService() = default;

// static
std::unique_ptr<KeyedService> BuildMockKeyPermissionsService(
    content::BrowserContext* browser_context) {
  return std::make_unique<MockKeyPermissionsService>();
}

}  // namespace platform_keys
}  // namespace chromeos
