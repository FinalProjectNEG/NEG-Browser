// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_ASH_IMAGE_DOWNLOADER_IMPL_H_
#define CHROME_BROWSER_UI_ASH_IMAGE_DOWNLOADER_IMPL_H_

#include "ash/public/cpp/image_downloader.h"

// Download images for ash using the active user profile. Fail and return null
// image if there is no active user.
class ImageDownloaderImpl : public ash::ImageDownloader {
 public:
  ImageDownloaderImpl();
  ~ImageDownloaderImpl() override;

  // ash::ImageDownloader:
  void Download(const GURL& url,
                const net::NetworkTrafficAnnotationTag& annotation_tag,
                ash::ImageDownloader::DownloadCallback callback) override;
};

#endif  // CHROME_BROWSER_UI_ASH_IMAGE_DOWNLOADER_IMPL_H_
