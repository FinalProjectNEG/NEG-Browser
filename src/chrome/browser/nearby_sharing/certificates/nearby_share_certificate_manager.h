// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_NEARBY_SHARING_CERTIFICATES_NEARBY_SHARE_CERTIFICATE_MANAGER_H_
#define CHROME_BROWSER_NEARBY_SHARING_CERTIFICATES_NEARBY_SHARE_CERTIFICATE_MANAGER_H_

#include <vector>

#include "base/callback.h"
#include "base/containers/span.h"
#include "base/observer_list.h"
#include "base/observer_list_types.h"
#include "base/optional.h"
#include "chrome/browser/nearby_sharing/certificates/nearby_share_decrypted_public_certificate.h"
#include "chrome/browser/nearby_sharing/certificates/nearby_share_encrypted_metadata_key.h"
#include "chrome/browser/nearby_sharing/certificates/nearby_share_private_certificate.h"
#include "chrome/browser/nearby_sharing/proto/rpc_resources.pb.h"
#include "chrome/browser/ui/webui/nearby_share/public/mojom/nearby_share_settings.mojom.h"

// The Nearby Share certificate manager maintains the local device's private
// certificates and contacts' public certificates. The manager communicates with
// the Nearby server to 1) download contacts' public certificates and 2) upload
// local device public certificates to be distributed to contacts.
//
// The class contatins methods for performing crypto operations with the
// currently valid private certificate of a given visibility, such as signing a
// payload or generating an encrypted metadata key for an advertisement. For
// crypto operations related to public certificates, such as verifying a
// payload, find and decrypt the relevant certificate with
// DecryptPublicCertificate(), then use the
// NearbyShareDecryptedPublicCertificate class to perform the crypto operations.
// NOTE: The NearbySharePrivateCertificate class is not directly returned
// because storage needs to be update whenever salts are consumed for metadata
// key encryption.
//
// Observers are notified of any changes to private/public certificates.
class NearbyShareCertificateManager {
 public:
  class Observer : public base::CheckedObserver {
   public:
    virtual void OnPublicCertificatesDownloaded() = 0;
    virtual void OnPrivateCertificatesChanged() = 0;
  };

  using CertDecryptedCallback = base::OnceCallback<void(
      base::Optional<NearbyShareDecryptedPublicCertificate>)>;

  NearbyShareCertificateManager();
  virtual ~NearbyShareCertificateManager();

  void AddObserver(Observer* observer);
  void RemoveObserver(Observer* observer);

  // Starts/Stops certificate task scheduling.
  void Start();
  void Stop();
  bool is_running() { return is_running_; }

  // Encrypts the metadata encryption key of the currently valid private
  // certificate with |visibility|. Returns base::nullopt if there is no valid
  // private certificate with |visibility|, if the encryption failed, or if
  // there are no remaining salts.
  base::Optional<NearbyShareEncryptedMetadataKey>
  EncryptPrivateCertificateMetadataKey(
      nearby_share::mojom::Visibility visibility);

  // Signs the input |payload| using the currently valid private certificate
  // with |visibility|. Returns base::nullopt if there is no valid private
  // certificate with |visibility| or if the signing was unsuccessful.
  base::Optional<std::vector<uint8_t>> SignWithPrivateCertificate(
      nearby_share::mojom::Visibility visibility,
      base::span<const uint8_t> payload) const;

  // Creates a hash of the |authentication_token| using the currently valid
  // private certificate. Returns base::nullopt if there is no valid private
  // certificate with |visibility|.
  base::Optional<std::vector<uint8_t>>
  HashAuthenticationTokenWithPrivateCertificate(
      nearby_share::mojom::Visibility visibility,
      base::span<const uint8_t> authentication_token) const;

  // Returns all local device private certificates of |visibility| converted to
  // public certificates. The public certificates' for_selected_contacts fields
  // will be set to reflect the |visibility|. NOTE: Only certificates with the
  // requested visibility will be returned; if selected-contacts visibility is
  // passed in, the all-contacts visibility certificates will *not* be returned
  // as well.
  virtual std::vector<nearbyshare::proto::PublicCertificate>
  GetPrivateCertificatesAsPublicCertificates(
      nearby_share::mojom::Visibility visibility) = 0;

  // Returns in |callback| the public certificate that is able to be decrypted
  // using |encrypted_metadata_key|, and returns base::nullopt if no such public
  // certificate exists.
  virtual void GetDecryptedPublicCertificate(
      NearbyShareEncryptedMetadataKey encrypted_metadata_key,
      CertDecryptedCallback callback) = 0;

  // Makes an RPC call to the Nearby server to retrieve all public certificates
  // available to the local device. These are also downloaded periodically.
  // Observers are notified when all public certificate downloads succeed via
  // OnPublicCertificatesDownloaded().
  virtual void DownloadPublicCertificates() = 0;

 protected:
  virtual void OnStart() = 0;
  virtual void OnStop() = 0;

  // Returns the currently valid private certificate with |visibility|, or
  // returns base::nullopt if one does not exist.
  virtual base::Optional<NearbySharePrivateCertificate>
  GetValidPrivateCertificate(
      nearby_share::mojom::Visibility visibility) const = 0;

  // Updates the existing record for |private_certificate|. If no such record
  // exists, this function does nothing.
  virtual void UpdatePrivateCertificateInStorage(
      const NearbySharePrivateCertificate& private_certificate) = 0;

  void NotifyPublicCertificatesDownloaded();
  void NotifyPrivateCertificatesChanged();

 private:
  bool is_running_ = false;
  base::ObserverList<Observer> observers_;
};

#endif  // CHROME_BROWSER_NEARBY_SHARING_CERTIFICATES_NEARBY_SHARE_CERTIFICATE_MANAGER_H_
