// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/nearby_sharing/local_device_data/nearby_share_local_device_data_manager.h"

const size_t kNearbyShareDeviceNameMaxLength = 32;

NearbyShareLocalDeviceDataManager::NearbyShareLocalDeviceDataManager() =
    default;

NearbyShareLocalDeviceDataManager::~NearbyShareLocalDeviceDataManager() =
    default;

void NearbyShareLocalDeviceDataManager::AddObserver(Observer* observer) {
  observers_.AddObserver(observer);
}

void NearbyShareLocalDeviceDataManager::RemoveObserver(Observer* observer) {
  observers_.RemoveObserver(observer);
}

void NearbyShareLocalDeviceDataManager::Start() {
  if (is_running_)
    return;

  is_running_ = true;
  OnStart();
}

void NearbyShareLocalDeviceDataManager::Stop() {
  if (!is_running_)
    return;

  is_running_ = false;
  OnStop();
}

void NearbyShareLocalDeviceDataManager::NotifyLocalDeviceDataChanged(
    bool did_device_name_change,
    bool did_full_name_change,
    bool did_icon_url_change) {
  for (auto& observer : observers_) {
    observer.OnLocalDeviceDataChanged(
        did_device_name_change, did_full_name_change, did_icon_url_change);
  }
}
