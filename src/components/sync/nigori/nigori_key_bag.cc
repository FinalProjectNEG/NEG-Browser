// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/sync/nigori/nigori_key_bag.h"

#include <utility>

#include "base/logging.h"
#include "base/notreached.h"
#include "components/sync/nigori/nigori.h"
#include "components/sync/protocol/nigori_specifics.pb.h"

namespace syncer {
namespace {

std::string ComputeNigoriName(const Nigori& nigori) {
  std::string key_name;
  nigori.Permute(Nigori::Password, kNigoriKeyName, &key_name);
  return key_name;
}

// Note that |key_name| is redundant but computing the name from |nigori| can be
// expensive.
sync_pb::NigoriKey NigoriToProto(const Nigori& nigori,
                                 const std::string& key_name) {
  DCHECK_EQ(key_name, ComputeNigoriName(nigori));

  sync_pb::NigoriKey proto;
  proto.set_deprecated_name(key_name);
  nigori.ExportKeys(proto.mutable_deprecated_user_key(),
                    proto.mutable_encryption_key(), proto.mutable_mac_key());
  return proto;
}

std::unique_ptr<Nigori> CloneNigori(const Nigori& nigori) {
  std::string user_key;
  std::string encryption_key;
  std::string mac_key;
  nigori.ExportKeys(&user_key, &encryption_key, &mac_key);

  std::unique_ptr<Nigori> nigori_copy =
      Nigori::CreateByImport(user_key, encryption_key, mac_key);
  DCHECK(nigori_copy);
  return nigori_copy;
}

}  // namespace

// static
NigoriKeyBag NigoriKeyBag::CreateEmpty() {
  return NigoriKeyBag();
}

// static
NigoriKeyBag NigoriKeyBag::CreateFromProto(const sync_pb::NigoriKeyBag& proto) {
  NigoriKeyBag output;
  for (const sync_pb::NigoriKey& key : proto.key()) {
    if (output.AddKeyFromProto(key).empty()) {
      // TODO(crbug.com/922900): Consider propagating this error to callers such
      // that they can do smarter handling.
      DLOG(ERROR) << "Invalid NigoriKey protocol buffer message.";
    }
  }
  return output;
}

NigoriKeyBag::NigoriKeyBag(NigoriKeyBag&& other) = default;

NigoriKeyBag::~NigoriKeyBag() = default;

void NigoriKeyBag::CopyFrom(const NigoriKeyBag& other) {
  nigori_map_.clear();
  AddAllUnknownKeysFrom(other);
}

sync_pb::NigoriKeyBag NigoriKeyBag::ToProto() const {
  sync_pb::NigoriKeyBag output;
  for (const auto& key_name_and_nigori : nigori_map_) {
    *output.add_key() =
        NigoriToProto(*key_name_and_nigori.second, key_name_and_nigori.first);
  }
  return output;
}

NigoriKeyBag NigoriKeyBag::Clone() const {
  NigoriKeyBag copy;
  copy.AddAllUnknownKeysFrom(*this);
  return copy;
}

size_t NigoriKeyBag::size() const {
  return nigori_map_.size();
}

bool NigoriKeyBag::HasKey(const std::string& key_name) const {
  return nigori_map_.count(key_name) != 0;
}

sync_pb::NigoriKey NigoriKeyBag::ExportKey(const std::string& key_name) const {
  DCHECK(HasKey(key_name));
  sync_pb::NigoriKey key =
      NigoriToProto(*nigori_map_.find(key_name)->second, key_name);
  // For exported keys, clients never consumed the key name, so it's safe to
  // clear the deprecated field.
  key.clear_deprecated_name();
  return key;
}

std::string NigoriKeyBag::AddKey(std::unique_ptr<Nigori> nigori) {
  DCHECK(nigori);
  const std::string key_name = ComputeNigoriName(*nigori);
  if (key_name.empty()) {
    NOTREACHED();
    return key_name;
  }
  nigori_map_.emplace(key_name, std::move(nigori));
  return key_name;
}

std::string NigoriKeyBag::AddKeyFromProto(const sync_pb::NigoriKey& key) {
  std::unique_ptr<Nigori> nigori = Nigori::CreateByImport(
      key.deprecated_user_key(), key.encryption_key(), key.mac_key());
  if (!nigori) {
    return std::string();
  }

  const std::string key_name = ComputeNigoriName(*nigori);
  if (key_name.empty()) {
    return std::string();
  }

  nigori_map_[key_name] = std::move(nigori);
  return key_name;
}

void NigoriKeyBag::AddAllUnknownKeysFrom(const NigoriKeyBag& other) {
  for (const auto& key_name_and_nigori : other.nigori_map_) {
    // Only use this key if we don't already know about it.
    nigori_map_.emplace(key_name_and_nigori.first,
                        CloneNigori(*key_name_and_nigori.second));
  }
}

bool NigoriKeyBag::EncryptWithKey(
    const std::string& key_name,
    const std::string& input,
    sync_pb::EncryptedData* encrypted_output) const {
  DCHECK(encrypted_output);
  DCHECK(HasKey(key_name));

  encrypted_output->Clear();

  if (!nigori_map_.find(key_name)->second->Encrypt(
          input, encrypted_output->mutable_blob())) {
    DLOG(ERROR) << "Failed to encrypt data.";
    return false;
  }

  encrypted_output->set_key_name(key_name);
  return true;
}

bool NigoriKeyBag::CanDecrypt(
    const sync_pb::EncryptedData& encrypted_input) const {
  return HasKey(encrypted_input.key_name());
}

bool NigoriKeyBag::Decrypt(const sync_pb::EncryptedData& encrypted_input,
                           std::string* decrypted_output) const {
  DCHECK(decrypted_output);

  decrypted_output->clear();

  auto it = nigori_map_.find(encrypted_input.key_name());
  if (it == nigori_map_.end()) {
    // The key used to encrypt the blob is not part of the set of installed
    // nigoris.
    return false;
  }

  return it->second->Decrypt(encrypted_input.blob(), decrypted_output);
}

NigoriKeyBag::NigoriKeyBag() = default;

}  // namespace syncer
