// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ASH_AMBIENT_BACKDROP_AMBIENT_BACKEND_CONTROLLER_IMPL_H_
#define ASH_AMBIENT_BACKDROP_AMBIENT_BACKEND_CONTROLLER_IMPL_H_

#include <array>
#include <memory>
#include <string>
#include <utility>

#include "ash/public/cpp/ambient/ambient_backend_controller.h"
#include "ash/public/cpp/ambient/ambient_client.h"
#include "ash/public/cpp/ambient/common/ambient_settings.h"
#include "base/memory/weak_ptr.h"
#include "base/optional.h"
#include "chromeos/assistant/internal/ambient/backdrop_client_config.h"

namespace ash {

class BackdropURLLoader;

// The Backdrop client implementation of AmbientBackendController.
class AmbientBackendControllerImpl : public AmbientBackendController {
 public:
  AmbientBackendControllerImpl();
  ~AmbientBackendControllerImpl() override;

  // AmbientBackendController:
  void FetchScreenUpdateInfo(
      int num_topics,
      OnScreenUpdateInfoFetchedCallback callback) override;
  void GetSettings(GetSettingsCallback callback) override;
  void UpdateSettings(const AmbientSettings& settings,
                      UpdateSettingsCallback callback) override;
  void FetchSettingPreview(int preview_width,
                           int preview_height,
                           OnSettingPreviewFetchedCallback callback) override;
  void FetchPersonalAlbums(int banner_width,
                           int banner_height,
                           int num_albums,
                           const std::string& resume_token,
                           OnPersonalAlbumsFetchedCallback callback) override;
  void FetchSettingsAndAlbums(
      int banner_width,
      int banner_height,
      int num_albums,
      OnSettingsAndAlbumsFetchedCallback callback) override;
  void SetPhotoRefreshInterval(base::TimeDelta interval) override;
  void FetchWeather(FetchWeatherCallback callback) override;
  const std::array<const char*, 2>& GetBackupPhotoUrls() const override;

 private:
  using BackdropClientConfig = chromeos::ambient::BackdropClientConfig;
  void RequestAccessToken(AmbientClient::GetAccessTokenCallback callback);

  void FetchScreenUpdateInfoInternal(int num_topics,
                                     OnScreenUpdateInfoFetchedCallback callback,
                                     const std::string& gaia_id,
                                     const std::string& access_token);

  void OnScreenUpdateInfoFetched(
      OnScreenUpdateInfoFetchedCallback callback,
      std::unique_ptr<BackdropURLLoader> backdrop_url_loader,
      std::unique_ptr<std::string> response);

  void StartToGetSettings(GetSettingsCallback callback,
                          const std::string& gaia_id,
                          const std::string& access_token);

  void OnGetSettings(GetSettingsCallback callback,
                     std::unique_ptr<BackdropURLLoader> backdrop_url_loader,
                     std::unique_ptr<std::string> response);

  void StartToUpdateSettings(const AmbientSettings& settings,
                             UpdateSettingsCallback callback,
                             const std::string& gaia_id,
                             const std::string& access_token);

  void OnUpdateSettings(UpdateSettingsCallback callback,
                        const AmbientSettings& settings,
                        std::unique_ptr<BackdropURLLoader> backdrop_url_loader,
                        std::unique_ptr<std::string> response);

  void FetchSettingPreviewInternal(int preview_width,
                                   int preview_height,
                                   OnSettingPreviewFetchedCallback callback,
                                   const std::string& gaia_id,
                                   const std::string& access_token);

  void OnSettingPreviewFetched(
      OnSettingPreviewFetchedCallback callback,
      std::unique_ptr<BackdropURLLoader> backdrop_url_loader,
      std::unique_ptr<std::string> response);

  void FetchPersonalAlbumsInternal(int banner_width,
                                   int banner_height,
                                   int num_albums,
                                   const std::string& resume_token,
                                   OnPersonalAlbumsFetchedCallback callback,
                                   const std::string& gaia_id,
                                   const std::string& access_token);

  void OnPersonalAlbumsFetched(
      OnPersonalAlbumsFetchedCallback callback,
      std::unique_ptr<BackdropURLLoader> backdrop_url_loader,
      std::unique_ptr<std::string> response);

  void OnSettingsFetched(base::RepeatingClosure on_done,
                         const base::Optional<ash::AmbientSettings>& settings);

  void OnAlbumsFetched(base::RepeatingClosure on_done,
                       ash::PersonalAlbums personal_albums);

  void OnSettingsAndAlbumsFetched(OnSettingsAndAlbumsFetchedCallback callback);

  // Temporary store for FetchSettingsAndAlbums() when |GetSettingsCallback|
  // called. |settings_| will be base::nullopt if server returns with error.
  base::Optional<ash::AmbientSettings> settings_;

  // Temporary store for FetchSettingsAndAlbums() when
  // |OnPersonalAlbumsFetchedCallback| called. |personal_albums_| will contains
  // empty values if server returns with error.
  ash::PersonalAlbums personal_albums_;

  BackdropClientConfig backdrop_client_config_;

  base::WeakPtrFactory<AmbientBackendControllerImpl> weak_factory_{this};
};

}  // namespace ash

#endif  // ASH_AMBIENT_BACKDROP_AMBIENT_BACKEND_CONTROLLER_IMPL_H_
