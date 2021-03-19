// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_POLICY_MESSAGING_LAYER_ENCRYPTION_ENCRYPTION_H_
#define CHROME_BROWSER_POLICY_MESSAGING_LAYER_ENCRYPTION_ENCRYPTION_H_

#include <string>
#include <utility>

#include "base/callback.h"
#include "base/memory/ref_counted.h"
#include "base/memory/scoped_refptr.h"
#include "base/optional.h"
#include "base/strings/string_piece.h"
#include "chrome/browser/policy/messaging_layer/util/status.h"
#include "chrome/browser/policy/messaging_layer/util/statusor.h"
#include "components/policy/proto/record.pb.h"

namespace reporting {

// Full implementation of Encryptor, intended for use in reporting client.
// ChaCha20_Poly1305 AEAD encryption of a record in place with symmetric key.
// Curve25519 encryption of the symmetric key with asymmetric public key.
//
// We generate new Curve25519 public/private keys pair for each record.
// Then we produce Curve25519 shared secret from our private key and peer's
// public key, and use it for ChaCha20_Poly1305 AEAD encryption of the record.
// We send out our public value (calling it encrypted symmetric key) together
// with encrypted record.
//
// Upon receiving the encrypted message the peer will produce the same shared
// secret by combining their private key and our public key, and use it as
// a symmetric key for ChaCha20_Poly1305 decryption and validation of the
// record.
//
// Instantiated by a factory:
//   StatusOr<scoped_refptr<Encryptor>> Create();
// The implementation class should never be used directly by the client code.
class Encryptor : public base::RefCountedThreadSafe<Encryptor> {
 public:
  // Encryption record handle, which is created by |OpenRecord| and can accept
  // pieces of data to be encrypted as one record by calling |AddToRecord|
  // multiple times. Resulting encrypted record is available once |CloseRecord|
  // is called.
  class Handle {
   public:
    explicit Handle(scoped_refptr<Encryptor> encryptor);
    Handle(const Handle& other) = delete;
    Handle& operator=(const Handle& other) = delete;
    ~Handle();

    // Adds piece of data to the record.
    void AddToRecord(base::StringPiece data,
                     base::OnceCallback<void(Status)> cb);

    // Closes and encrypts the record, hands over the data (encrypted with
    // symmetric key) and the key (encrypted with asymmetric key) to be recorded
    // by the client (or Status if unsuccessful). Self-destructs after the
    // callback.
    void CloseRecord(base::OnceCallback<void(StatusOr<EncryptedRecord>)> cb);

   private:
    // Helper method to compose EncryptedRecord. Called by |CloseRecord|
    // as a callback after asynchronous retrieval of the asymmetric key.
    void ProduceEncryptedRecord(
        base::OnceCallback<void(StatusOr<EncryptedRecord>)> cb,
        StatusOr<std::string> asymmetric_key_result);

    // Accumulated data to encrypt.
    std::string record_;

    scoped_refptr<Encryptor> encryptor_;
  };

  // Factory method to instantiate the Encryptor.
  static StatusOr<scoped_refptr<Encryptor>> Create();

  // Factory method creates new record to collect data and encrypt them.
  // Hands the Handle raw pointer over to the callback, or error status).
  void OpenRecord(base::OnceCallback<void(StatusOr<Handle*>)> cb);

  // Delivers public asymmetric key to the implementation.
  // To affect specific record, must happen before Handle::CloseRecord
  // (it is OK to do it after OpenRecord and Handle::AddToRecord).
  // Executes on a sequenced thread, returns with callback.
  void UpdateAsymmetricKey(base::StringPiece new_key,
                           base::OnceCallback<void(Status)> response_cb);

  // Retrieves the current public key.
  // Executes on a sequenced thread, returns with callback.
  void RetrieveAsymmetricKey(
      base::OnceCallback<void(StatusOr<std::string>)> cb);

 private:
  friend class base::RefCountedThreadSafe<Encryptor>;
  Encryptor();
  ~Encryptor();

  // Public key used for asymmetric encryption of symmetric key.
  base::Optional<std::string> asymmetric_key_;

  // Sequential task runner for all asymmetric_key_ activities: update, read.
  scoped_refptr<base::SequencedTaskRunner>
      asymmetric_key_sequenced_task_runner_;

  SEQUENCE_CHECKER(asymmetric_key_sequence_checker_);
};

}  // namespace reporting

#endif  // CHROME_BROWSER_POLICY_MESSAGING_LAYER_ENCRYPTION_ENCRYPTION_H_
