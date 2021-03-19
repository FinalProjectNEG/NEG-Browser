// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_ASH_HOLDING_SPACE_HOLDING_SPACE_KEYED_SERVICE_H_
#define CHROME_BROWSER_UI_ASH_HOLDING_SPACE_HOLDING_SPACE_KEYED_SERVICE_H_

#include <memory>
#include <vector>

#include "ash/public/cpp/holding_space/holding_space_model.h"
#include "base/scoped_observer.h"
#include "base/strings/string16.h"
#include "chrome/browser/profiles/profile_manager.h"
#include "chrome/browser/profiles/profile_manager_observer.h"
#include "chrome/browser/ui/ash/holding_space/holding_space_client_impl.h"
#include "chrome/browser/ui/ash/holding_space/holding_space_keyed_service_delegate.h"
#include "chrome/browser/ui/ash/holding_space/holding_space_thumbnail_loader.h"
#include "components/account_id/account_id.h"
#include "components/keyed_service/core/keyed_service.h"
#include "url/gurl.h"

class GURL;

namespace base {
class FilePath;
}  // namespace base

namespace user_prefs {
class PrefRegistrySyncable;
}  // namespace user_prefs

namespace storage {
class FileSystemURL;
}  // namespace storage

namespace ash {

// Browser context keyed service that:
// *   Manages the temporary holding space per-profile data model.
// *   Serves as an entry point to add holding space items from Chrome.
class HoldingSpaceKeyedService : public KeyedService,
                                 public ProfileManagerObserver {
 public:
  HoldingSpaceKeyedService(Profile* profile, const AccountId& account_id);
  HoldingSpaceKeyedService(const HoldingSpaceKeyedService& other) = delete;
  HoldingSpaceKeyedService& operator=(const HoldingSpaceKeyedService& other) =
      delete;
  ~HoldingSpaceKeyedService() override;

  // Registers profile preferences for holding space.
  static void RegisterProfilePrefs(user_prefs::PrefRegistrySyncable* registry);

  // Adds a pinned file item identified by the provided file system URL.
  void AddPinnedFile(const storage::FileSystemURL& file_system_url);

  // Removes a pinned file item identified by the provided file system URL.
  // No-op if the file is not present in the holding space.
  void RemovePinnedFile(const storage::FileSystemURL& file_system_url);

  // Returns whether the holding space contains a pinned file identified by a
  // file system URL.
  bool ContainsPinnedFile(const storage::FileSystemURL& file_system_url) const;

  // Returns the list of pinned files in the holding space. It returns the files
  // files system URLs as GURLs.
  std::vector<GURL> GetPinnedFiles() const;

  // Adds a screenshot item backed by the provided absolute file path.
  // The path is expected to be under a mount point path recognized by the file
  // manager app (otherwise, the item will be dropped silently).
  void AddScreenshot(const base::FilePath& screenshot_path);

  // Adds a download item backed by the provided absolute file path.
  void AddDownload(const base::FilePath& download_path);

  // Adds a nearby share item backed by the provided absolute file path.
  void AddNearbyShare(const base::FilePath& nearby_share_path);

  // Adds the specified `item` to the holding space model.
  void AddItem(std::unique_ptr<HoldingSpaceItem> item);

  const HoldingSpaceClient* client_for_testing() const {
    return &holding_space_client_;
  }

  const HoldingSpaceModel* model_for_testing() const {
    return &holding_space_model_;
  }

  HoldingSpaceThumbnailLoader* thumbnail_loader_for_testing() {
    return &thumbnail_loader_;
  }

 private:
  // KeyedService:
  void Shutdown() override;

  // ProfileManagerObserver:
  void OnProfileAdded(Profile* profile) override;

  // Invoked when the associated profile is ready.
  void OnProfileReady();

  // Invoked when the specified `file_path` is removed.
  void OnFileRemoved(const base::FilePath& file_path);

  // Invoked when holding space persistence has been restored.
  void OnPersistenceRestored();

  Profile* const profile_;
  const AccountId account_id_;

  HoldingSpaceClientImpl holding_space_client_;
  HoldingSpaceModel holding_space_model_;

  HoldingSpaceThumbnailLoader thumbnail_loader_;

  // The `HoldingSpaceKeyedService` owns a collection of `delegates_` which are
  // each tasked with an independent area of responsibility on behalf of the
  // service. They operate autonomously of one another.
  std::vector<std::unique_ptr<HoldingSpaceKeyedServiceDelegate>> delegates_;

  ScopedObserver<ProfileManager, ProfileManagerObserver>
      profile_manager_observer_{this};

  base::WeakPtrFactory<HoldingSpaceKeyedService> weak_factory_{this};
};

}  // namespace ash

#endif  // CHROME_BROWSER_UI_ASH_HOLDING_SPACE_HOLDING_SPACE_KEYED_SERVICE_H_
