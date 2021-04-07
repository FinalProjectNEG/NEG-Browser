// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/arc/test/fake_wallpaper_instance.h"

#include <utility>

#include "base/bind.h"
#include "base/bind_helpers.h"

namespace arc {

FakeWallpaperInstance::FakeWallpaperInstance() = default;

FakeWallpaperInstance::~FakeWallpaperInstance() = default;

void FakeWallpaperInstance::InitDeprecated(
    mojo::PendingRemote<mojom::WallpaperHost> host_remote) {
  Init(std::move(host_remote), base::DoNothing());
}

void FakeWallpaperInstance::Init(
    mojo::PendingRemote<mojom::WallpaperHost> host_remote,
    InitCallback callback) {
  host_remote_.reset();
  host_remote_.Bind(std::move(host_remote));
  std::move(callback).Run();
}

void FakeWallpaperInstance::OnWallpaperChanged(int32_t wallpaper_id) {
  changed_ids_.push_back(wallpaper_id);
}

}  // namespace arc
