// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROMEOS_COMPONENTS_SMBFS_SMBFS_HOST_H_
#define CHROMEOS_COMPONENTS_SMBFS_SMBFS_HOST_H_

#include <memory>

#include "base/callback.h"
#include "base/component_export.h"
#include "base/files/file.h"
#include "base/files/file_path.h"
#include "base/macros.h"
#include "chromeos/components/smbfs/mojom/smbfs.mojom.h"
#include "chromeos/disks/mount_point.h"
#include "mojo/public/cpp/bindings/pending_receiver.h"
#include "mojo/public/cpp/bindings/remote.h"

namespace smbfs {

// SmbFsHost is a connection to a running instance of smbfs. It exposes methods
// provided by smbfs over Mojo (eg. server-side copy), and provides access to
// the host from smbfs using the Delegate interface. Destroying SmbFsHost will
// unmount and clean up the smbfs instance.
class COMPONENT_EXPORT(SMBFS) SmbFsHost {
 public:
  class Delegate {
   public:
    virtual ~Delegate();

    // Notification that the smbfs process is no longer connected via Mojo.
    virtual void OnDisconnected() = 0;

    using RequestCredentialsCallback =
        base::OnceCallback<void(bool cancel,
                                const std::string& username,
                                const std::string& workgroup,
                                const std::string& password)>;
    // Request credentials from the user. If the user dismisses the request, run
    // |callback| with |cancel| = true. Otherwise, run |callback| with the
    // credentials provided by the user and |cancel| = false.
    virtual void RequestCredentials(RequestCredentialsCallback callback) = 0;
  };

  SmbFsHost(std::unique_ptr<chromeos::disks::MountPoint> mount_point,
            Delegate* delegate,
            mojo::Remote<mojom::SmbFs> smbfs_remote,
            mojo::PendingReceiver<mojom::SmbFsDelegate> delegate_receiver);
  ~SmbFsHost();

  // Returns the path where SmbFS is mounted.
  const base::FilePath& mount_path() const {
    return mount_point_->mount_path();
  }

  using UnmountCallback = base::OnceCallback<void(chromeos::MountError)>;
  void Unmount(UnmountCallback callback);

  // Request any credentials saved by smbfs are deleted.
  using RemoveSavedCredentialsCallback = base::OnceCallback<void(bool)>;
  void RemoveSavedCredentials(RemoveSavedCredentialsCallback callback);

  // Recursively delete |path| by making a Mojo request to smbfs.
  using DeleteRecursivelyCallback = base::OnceCallback<void(base::File::Error)>;
  void DeleteRecursively(const base::FilePath& path,
                         DeleteRecursivelyCallback callback);

 private:
  // Mojo disconnection handler.
  void OnDisconnect();

  // Called after cros-disks has attempted to unmount the share.
  void OnUnmountDone(SmbFsHost::UnmountCallback callback,
                     chromeos::MountError result);

  // Callback for mojom::SmbFs::RemoveSavedCredentials().
  void OnRemoveSavedCredentialsDone(RemoveSavedCredentialsCallback callback,
                                    bool success);

  // Called after smbfs completes a DeleteRecursively operation.
  void OnDeleteRecursivelyDone(DeleteRecursivelyCallback callback,
                               smbfs::mojom::DeleteRecursivelyError error);

  const std::unique_ptr<chromeos::disks::MountPoint> mount_point_;
  Delegate* const delegate_;

  mojo::Remote<mojom::SmbFs> smbfs_;
  std::unique_ptr<mojom::SmbFsDelegate> delegate_impl_;

  DISALLOW_COPY_AND_ASSIGN(SmbFsHost);
};

}  // namespace smbfs

#endif  // CHROMEOS_COMPONENTS_SMBFS_SMBFS_HOST_H_
