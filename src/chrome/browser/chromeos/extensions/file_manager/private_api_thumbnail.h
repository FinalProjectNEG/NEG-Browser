// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// This file provides API functions to fetch external thumbnails for filesystem
// providers that support it.

#ifndef CHROME_BROWSER_CHROMEOS_EXTENSIONS_FILE_MANAGER_PRIVATE_API_THUMBNAIL_H_
#define CHROME_BROWSER_CHROMEOS_EXTENSIONS_FILE_MANAGER_PRIVATE_API_THUMBNAIL_H_

#include <memory>
#include <string>

#include "chrome/browser/chromeos/extensions/file_manager/private_api_base.h"

#include "chrome/browser/extensions/chrome_extension_function_details.h"
#include "chrome/services/printing/public/mojom/pdf_thumbnailer.mojom.h"
#include "mojo/public/cpp/bindings/remote.h"

class SkBitmap;

namespace extensions {

// Base class for thumbnail functions
class FileManagerPrivateGetThumbnailFunction : public LoggedExtensionFunction {
 public:
  FileManagerPrivateGetThumbnailFunction();

 protected:
  ~FileManagerPrivateGetThumbnailFunction() override = default;

  // Responds with a base64 encoded PNG thumbnail data.
  void SendEncodedThumbnail(std::string thumbnail_data_url);

  const ChromeExtensionFunctionDetails chrome_details_;
};

class FileManagerPrivateInternalGetDriveThumbnailFunction
    : public FileManagerPrivateGetThumbnailFunction {
 public:
  DECLARE_EXTENSION_FUNCTION("fileManagerPrivateInternal.getDriveThumbnail",
                             FILEMANAGERPRIVATEINTERNAL_GETDRIVETHUMBNAIL)

  FileManagerPrivateInternalGetDriveThumbnailFunction();

 protected:
  ~FileManagerPrivateInternalGetDriveThumbnailFunction() override;

  // ExtensionFunction overrides.
  ResponseAction Run() override;

 private:
  // A callback invoked when thumbnail data has been generated.
  void GotThumbnail(const base::Optional<std::vector<uint8_t>>& data);
};

class FileManagerPrivateInternalGetPdfThumbnailFunction
    : public FileManagerPrivateGetThumbnailFunction {
 public:
  DECLARE_EXTENSION_FUNCTION("fileManagerPrivateInternal.getPdfThumbnail",
                             FILEMANAGERPRIVATEINTERNAL_GETPDFTHUMBNAIL)

  FileManagerPrivateInternalGetPdfThumbnailFunction();

 protected:
  ~FileManagerPrivateInternalGetPdfThumbnailFunction() override;

  // ExtensionFunction overrides.
  ResponseAction Run() override;

 private:
  // For a given |content| starts fetching the first page PDF thumbnail by
  // calling PdfThumbnailer from the printing service. The first parameters,
  // |size| is supplied by the JavaScript caller.
  void FetchThumbnail(const gfx::Size& size, const std::string& content);

  // Callback invoked by the thumbnailing service when a PDF thumbnail has been
  // generated. The solitary parameter |bitmap| is supplied by the callback.
  // If |bitmap| is null, an error occurred. Otherwise, |bitmap| contains the
  // generated thumbnail.
  void GotThumbnail(const SkBitmap& bitmap);

  // Handles a mojo channel disconnect event.
  void ThumbnailDisconnected();

  // Holds the channel to Printing PDF thumbnailing service. Bound only
  // when needed.
  mojo::Remote<printing::mojom::PdfThumbnailer> pdf_thumbnailer_;

  // The dots per inch (dpi) resolution at which the PDF is rendered to a
  // thumbnail. The value of 30 is selected so that a US Letter size page does
  // not overflow a kSize x kSize thumbnail.
  constexpr static int kDpi = 30;
};

}  // namespace extensions

#endif  // CHROME_BROWSER_CHROMEOS_EXTENSIONS_FILE_MANAGER_PRIVATE_API_THUMBNAIL_H_
