// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_CHROMEOS_PLATFORM_KEYS_KEY_PERMISSIONS_KEY_PERMISSIONS_SERVICE_H_
#define CHROME_BROWSER_CHROMEOS_PLATFORM_KEYS_KEY_PERMISSIONS_KEY_PERMISSIONS_SERVICE_H_

#include <memory>
#include <string>
#include <vector>

#include "base/callback_forward.h"
#include "chrome/browser/chromeos/platform_keys/platform_keys.h"
#include "components/keyed_service/core/keyed_service.h"

namespace chromeos {
namespace platform_keys {

using CanUserGrantPermissionForKeyCallback =
    base::OnceCallback<void(bool allowed)>;

using IsCorporateKeyCallback = base::OnceCallback<void(bool corporate)>;

using SetCorporateKeyCallback = base::OnceCallback<void(Status status)>;

// ** KeyPermissionService Responsibility **
// A KeyPermissionService instance is responsible for answering queries
// regarding platform keys permissions with respect to a specific profile.
//
// ** Corporate Usage **
// As not every key is meant for corporate usage but probably for the user's
// private usage, this class introduces the concept of tagging keys with the
// intended purpose of the key. Currently, the only usage that can be assigned
// to a key is "corporate".
// Every key that is generated by the chrome.enterprise.platformKeys API (which
// requires the user account to be managed), is marked for corporate usage.
// Any key that is generated or imported by other means is currently not marked
// for corporate usage.

class KeyPermissionsService : public KeyedService {
 public:
  KeyPermissionsService();
  ~KeyPermissionsService() override;

  // Determines if the user can grant any permission for |public_key_spki_der|
  // to extensions. |callback| will be invoked with the result.
  virtual void CanUserGrantPermissionForKey(
      const std::string& public_key_spki_der,
      CanUserGrantPermissionForKeyCallback callback) const = 0;

  // Determines if the key identified by |public_key_spki_der|is marked for
  // corporate usage. |callback| will be invoked with the result.
  virtual void IsCorporateKey(const std::string& public_key_spki_der,
                              IsCorporateKeyCallback callback) const = 0;

  // Marks the key identified by |public_key_spki_der| as corporate usage.
  // |callback| will be invoked with the resulting status.
  virtual void SetCorporateKey(const std::string& public_key_spki_der,
                               SetCorporateKeyCallback callback) const = 0;
};

}  // namespace platform_keys
}  // namespace chromeos

#endif  // CHROME_BROWSER_CHROMEOS_PLATFORM_KEYS_KEY_PERMISSIONS_KEY_PERMISSIONS_SERVICE_H_
