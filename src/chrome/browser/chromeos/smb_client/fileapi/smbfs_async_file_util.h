// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_CHROMEOS_SMB_CLIENT_FILEAPI_SMBFS_ASYNC_FILE_UTIL_H_
#define CHROME_BROWSER_CHROMEOS_SMB_CLIENT_FILEAPI_SMBFS_ASYNC_FILE_UTIL_H_

#include "base/memory/weak_ptr.h"
#include "storage/browser/file_system/async_file_util_adapter.h"

class Profile;

namespace chromeos {
namespace smb_client {

// The implementation of storage::AsyncFileUtil for SmbFs. This forwards to a
// AsyncFileUtil for native files by default.
// Note: Functions are executed on the IO thread.
class SmbFsAsyncFileUtil : public storage::AsyncFileUtilAdapter {
 public:
  explicit SmbFsAsyncFileUtil(Profile* profile);
  ~SmbFsAsyncFileUtil() override;

  SmbFsAsyncFileUtil() = delete;
  SmbFsAsyncFileUtil(const SmbFsAsyncFileUtil&) = delete;
  SmbFsAsyncFileUtil& operator=(const SmbFsAsyncFileUtil&) = delete;

  // storage::AsyncFileUtil overrides.
  void ReadDirectory(
      std::unique_ptr<storage::FileSystemOperationContext> context,
      const storage::FileSystemURL& url,
      ReadDirectoryCallback callback) override;

  void DeleteRecursively(
      std::unique_ptr<storage::FileSystemOperationContext> context,
      const storage::FileSystemURL& url,
      StatusCallback callback) override;

 private:
  // Wrapper that calls storage::AsyncFileUtilAdapter::ReadDirectory(),
  // bypassing virtual dispatch.
  void RealReadDirectory(
      std::unique_ptr<storage::FileSystemOperationContext> context,
      const storage::FileSystemURL& url,
      ReadDirectoryCallback callback);

  Profile* const profile_;

  base::WeakPtrFactory<SmbFsAsyncFileUtil> weak_factory_{this};
};

}  // namespace smb_client
}  // namespace chromeos

#endif  // CHROME_BROWSER_CHROMEOS_SMB_CLIENT_FILEAPI_SMBFS_ASYNC_FILE_UTIL_H_
