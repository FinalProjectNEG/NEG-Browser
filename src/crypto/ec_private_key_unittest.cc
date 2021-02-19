// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crypto/ec_private_key.h"

#include <stdint.h>

#include <memory>
#include <vector>

#include "base/stl_util.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace {

void ExpectKeysEqual(const crypto::ECPrivateKey* keypair1,
                     const crypto::ECPrivateKey* keypair2) {
  std::vector<uint8_t> privkey1;
  std::vector<uint8_t> privkey2;
  EXPECT_TRUE(keypair1->ExportPrivateKey(&privkey1));
  EXPECT_TRUE(keypair2->ExportPrivateKey(&privkey2));
  EXPECT_EQ(privkey1, privkey2);

  std::vector<uint8_t> pubkey1;
  std::vector<uint8_t> pubkey2;
  EXPECT_TRUE(keypair1->ExportPublicKey(&pubkey1));
  EXPECT_TRUE(keypair2->ExportPublicKey(&pubkey2));
  EXPECT_EQ(pubkey1, pubkey2);

  std::string raw_pubkey1;
  std::string raw_pubkey2;
  EXPECT_TRUE(keypair1->ExportRawPublicKey(&raw_pubkey1));
  EXPECT_TRUE(keypair2->ExportRawPublicKey(&raw_pubkey2));
  EXPECT_EQ(raw_pubkey1, raw_pubkey2);
}

}  // namespace

// Generate random private keys. Export, then re-import in several ways. We
// should get back the same exact public key, and the private key should have
// the same value and elliptic curve params.
TEST(ECPrivateKeyUnitTest, InitRandomTest) {
  std::unique_ptr<crypto::ECPrivateKey> keypair(crypto::ECPrivateKey::Create());
  ASSERT_TRUE(keypair);

  // Re-import as a PrivateKeyInfo.
  std::vector<uint8_t> privkey;
  EXPECT_TRUE(keypair->ExportPrivateKey(&privkey));
  std::unique_ptr<crypto::ECPrivateKey> keypair_copy =
      crypto::ECPrivateKey::CreateFromPrivateKeyInfo(privkey);
  ASSERT_TRUE(keypair_copy);
  ExpectKeysEqual(keypair.get(), keypair_copy.get());

  // Re-import as an EncryptedPrivateKeyInfo with kPassword1.
  std::vector<uint8_t> encrypted_privkey;
  EXPECT_TRUE(keypair->ExportEncryptedPrivateKey(&encrypted_privkey));
  keypair_copy = crypto::ECPrivateKey::CreateFromEncryptedPrivateKeyInfo(
      encrypted_privkey);
  ASSERT_TRUE(keypair_copy);
  ExpectKeysEqual(keypair.get(), keypair_copy.get());
}

TEST(ECPrivateKeyUnitTest, Copy) {
  std::unique_ptr<crypto::ECPrivateKey> keypair1(
      crypto::ECPrivateKey::Create());
  std::unique_ptr<crypto::ECPrivateKey> keypair2(keypair1->Copy());
  ASSERT_TRUE(keypair1);
  ASSERT_TRUE(keypair2);

  ExpectKeysEqual(keypair1.get(), keypair2.get());
}

TEST(ECPrivateKeyUnitTest, CreateFromPrivateKeyInfo) {
  static const uint8_t kPrivateKeyInfo[] = {
      0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
      0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
      0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02, 0x01, 0x01, 0x04, 0x20,
      0x07, 0x0f, 0x08, 0x72, 0x7a, 0xd4, 0xa0, 0x4a, 0x9c, 0xdd, 0x59, 0xc9,
      0x4d, 0x89, 0x68, 0x77, 0x08, 0xb5, 0x6f, 0xc9, 0x5d, 0x30, 0x77, 0x0e,
      0xe8, 0xd1, 0xc9, 0xce, 0x0a, 0x8b, 0xb4, 0x6a, 0xa1, 0x44, 0x03, 0x42,
      0x00, 0x04, 0xe6, 0x2b, 0x69, 0xe2, 0xbf, 0x65, 0x9f, 0x97, 0xbe, 0x2f,
      0x1e, 0x0d, 0x94, 0x8a, 0x4c, 0xd5, 0x97, 0x6b, 0xb7, 0xa9, 0x1e, 0x0d,
      0x46, 0xfb, 0xdd, 0xa9, 0xa9, 0x1e, 0x9d, 0xdc, 0xba, 0x5a, 0x01, 0xe7,
      0xd6, 0x97, 0xa8, 0x0a, 0x18, 0xf9, 0xc3, 0xc4, 0xa3, 0x1e, 0x56, 0xe2,
      0x7c, 0x83, 0x48, 0xdb, 0x16, 0x1a, 0x1c, 0xf5, 0x1d, 0x7e, 0xf1, 0x94,
      0x2d, 0x4b, 0xcf, 0x72, 0x22, 0xc1,
  };
  static const uint8_t kSubjectPublicKeyInfo[] = {
      0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
      0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
      0x42, 0x00, 0x04, 0xe6, 0x2b, 0x69, 0xe2, 0xbf, 0x65, 0x9f, 0x97, 0xbe,
      0x2f, 0x1e, 0x0d, 0x94, 0x8a, 0x4c, 0xd5, 0x97, 0x6b, 0xb7, 0xa9, 0x1e,
      0x0d, 0x46, 0xfb, 0xdd, 0xa9, 0xa9, 0x1e, 0x9d, 0xdc, 0xba, 0x5a, 0x01,
      0xe7, 0xd6, 0x97, 0xa8, 0x0a, 0x18, 0xf9, 0xc3, 0xc4, 0xa3, 0x1e, 0x56,
      0xe2, 0x7c, 0x83, 0x48, 0xdb, 0x16, 0x1a, 0x1c, 0xf5, 0x1d, 0x7e, 0xf1,
      0x94, 0x2d, 0x4b, 0xcf, 0x72, 0x22, 0xc1,
  };
  static const uint8_t kRawPublicKey[] = {
      0xe6, 0x2b, 0x69, 0xe2, 0xbf, 0x65, 0x9f, 0x97, 0xbe, 0x2f, 0x1e,
      0x0d, 0x94, 0x8a, 0x4c, 0xd5, 0x97, 0x6b, 0xb7, 0xa9, 0x1e, 0x0d,
      0x46, 0xfb, 0xdd, 0xa9, 0xa9, 0x1e, 0x9d, 0xdc, 0xba, 0x5a, 0x01,
      0xe7, 0xd6, 0x97, 0xa8, 0x0a, 0x18, 0xf9, 0xc3, 0xc4, 0xa3, 0x1e,
      0x56, 0xe2, 0x7c, 0x83, 0x48, 0xdb, 0x16, 0x1a, 0x1c, 0xf5, 0x1d,
      0x7e, 0xf1, 0x94, 0x2d, 0x4b, 0xcf, 0x72, 0x22, 0xc1,
  };

  std::unique_ptr<crypto::ECPrivateKey> key =
      crypto::ECPrivateKey::CreateFromPrivateKeyInfo(std::vector<uint8_t>(
          std::begin(kPrivateKeyInfo), std::end(kPrivateKeyInfo)));
  ASSERT_TRUE(key);

  std::vector<uint8_t> public_key;
  ASSERT_TRUE(key->ExportPublicKey(&public_key));
  EXPECT_EQ(std::vector<uint8_t>(std::begin(kSubjectPublicKeyInfo),
                                 std::end(kSubjectPublicKeyInfo)),
            public_key);

  std::string raw_public_key;
  ASSERT_TRUE(key->ExportRawPublicKey(&raw_public_key));
  EXPECT_EQ(std::string(reinterpret_cast<const char*>(kRawPublicKey),
                        sizeof(kRawPublicKey)),
            raw_public_key);
}

TEST(ECPrivateKeyUnitTest, DeriveFromSecret) {
  static const uint8_t kSecret[] = {
      0x90, 0x48, 0x0a, 0x51, 0x77, 0xa3, 0x72, 0xfb, 0xba, 0x0f, 0x08,
      0x5e, 0xc5, 0x6f, 0x8f, 0x6d, 0x1c, 0xaf, 0xa9, 0x8a, 0xdf, 0xa9,
      0x7c, 0x38, 0x70, 0x47, 0xb9, 0x72, 0xcc, 0x5c, 0xaa, 0xc2,
  };

  static const uint8_t kPrivateKeyInfo[] = {
      0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
      0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
      0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02, 0x01, 0x01, 0x04, 0x20,
      0x0e, 0x87, 0xc8, 0x4d, 0x92, 0x14, 0x52, 0x93, 0x96, 0xad, 0x63, 0x9a,
      0x6a, 0xa7, 0xeb, 0x56, 0x5c, 0xaf, 0xab, 0x69, 0x06, 0xd4, 0x37, 0xf8,
      0x7d, 0xd7, 0x04, 0xa9, 0xec, 0x6e, 0x2e, 0x96, 0xa1, 0x44, 0x03, 0x42,
      0x00, 0x04, 0xe2, 0xf5, 0x86, 0x4a, 0xf6, 0xe0, 0x7d, 0x19, 0x94, 0x2d,
      0x54, 0x16, 0x58, 0x98, 0x62, 0x78, 0xf2, 0x8f, 0x30, 0x77, 0x93, 0x7d,
      0x2c, 0x17, 0x29, 0xe5, 0x50, 0x42, 0xed, 0x8d, 0x6c, 0x31, 0x34, 0x16,
      0x20, 0x4f, 0xcc, 0x50, 0x09, 0xaf, 0x8d, 0x56, 0x56, 0x73, 0xe3, 0xb9,
      0x5a, 0x15, 0xbf, 0x73, 0x25, 0x91, 0xa0, 0xaf, 0x8f, 0x64, 0x19, 0xf4,
      0x17, 0x8e, 0x7a, 0x05, 0x76, 0x23,
  };

  static const uint8_t kSubjectPublicKeyInfo[] = {
      0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
      0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
      0x42, 0x00, 0x04, 0xe2, 0xf5, 0x86, 0x4a, 0xf6, 0xe0, 0x7d, 0x19, 0x94,
      0x2d, 0x54, 0x16, 0x58, 0x98, 0x62, 0x78, 0xf2, 0x8f, 0x30, 0x77, 0x93,
      0x7d, 0x2c, 0x17, 0x29, 0xe5, 0x50, 0x42, 0xed, 0x8d, 0x6c, 0x31, 0x34,
      0x16, 0x20, 0x4f, 0xcc, 0x50, 0x09, 0xaf, 0x8d, 0x56, 0x56, 0x73, 0xe3,
      0xb9, 0x5a, 0x15, 0xbf, 0x73, 0x25, 0x91, 0xa0, 0xaf, 0x8f, 0x64, 0x19,
      0xf4, 0x17, 0x8e, 0x7a, 0x05, 0x76, 0x23,
  };
  static const uint8_t kRawPublicKey[] = {
      0xe2, 0xf5, 0x86, 0x4a, 0xf6, 0xe0, 0x7d, 0x19, 0x94, 0x2d, 0x54,
      0x16, 0x58, 0x98, 0x62, 0x78, 0xf2, 0x8f, 0x30, 0x77, 0x93, 0x7d,
      0x2c, 0x17, 0x29, 0xe5, 0x50, 0x42, 0xed, 0x8d, 0x6c, 0x31, 0x34,
      0x16, 0x20, 0x4f, 0xcc, 0x50, 0x09, 0xaf, 0x8d, 0x56, 0x56, 0x73,
      0xe3, 0xb9, 0x5a, 0x15, 0xbf, 0x73, 0x25, 0x91, 0xa0, 0xaf, 0x8f,
      0x64, 0x19, 0xf4, 0x17, 0x8e, 0x7a, 0x05, 0x76, 0x23,
  };

  std::unique_ptr<crypto::ECPrivateKey> key(
      crypto::ECPrivateKey::DeriveFromSecret(kSecret));
  ASSERT_TRUE(key);

  std::vector<uint8_t> privkey;
  EXPECT_TRUE(key->ExportPrivateKey(&privkey));
  EXPECT_EQ(std::vector<uint8_t>(std::begin(kPrivateKeyInfo),
                                 std::end(kPrivateKeyInfo)),
            privkey);

  std::vector<uint8_t> public_key;
  ASSERT_TRUE(key->ExportPublicKey(&public_key));
  EXPECT_EQ(std::vector<uint8_t>(std::begin(kSubjectPublicKeyInfo),
                                 std::end(kSubjectPublicKeyInfo)),
            public_key);

  std::string raw_public_key;
  ASSERT_TRUE(key->ExportRawPublicKey(&raw_public_key));
  EXPECT_EQ(std::string(reinterpret_cast<const char*>(kRawPublicKey),
                        sizeof(kRawPublicKey)),
            raw_public_key);
}

TEST(ECPrivateKeyUnitTest, RSAPrivateKeyInfo) {
  static const uint8_t kPrivateKeyInfo[] = {
      0x30, 0x82, 0x02, 0x78, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a,
      0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82,
      0x02, 0x62, 0x30, 0x82, 0x02, 0x5e, 0x02, 0x01, 0x00, 0x02, 0x81, 0x81,
      0x00, 0xb8, 0x7f, 0x2b, 0x20, 0xdc, 0x7c, 0x9b, 0x0c, 0xdc, 0x51, 0x61,
      0x99, 0x0d, 0x36, 0x0f, 0xd4, 0x66, 0x88, 0x08, 0x55, 0x84, 0xd5, 0x3a,
      0xbf, 0x2b, 0xa4, 0x64, 0x85, 0x7b, 0x0c, 0x04, 0x13, 0x3f, 0x8d, 0xf4,
      0xbc, 0x38, 0x0d, 0x49, 0xfe, 0x6b, 0xc4, 0x5a, 0xb0, 0x40, 0x53, 0x3a,
      0xd7, 0x66, 0x09, 0x0f, 0x9e, 0x36, 0x74, 0x30, 0xda, 0x8a, 0x31, 0x4f,
      0x1f, 0x14, 0x50, 0xd7, 0xc7, 0x20, 0x94, 0x17, 0xde, 0x4e, 0xb9, 0x57,
      0x5e, 0x7e, 0x0a, 0xe5, 0xb2, 0x65, 0x7a, 0x89, 0x4e, 0xb6, 0x47, 0xff,
      0x1c, 0xbd, 0xb7, 0x38, 0x13, 0xaf, 0x47, 0x85, 0x84, 0x32, 0x33, 0xf3,
      0x17, 0x49, 0xbf, 0xe9, 0x96, 0xd0, 0xd6, 0x14, 0x6f, 0x13, 0x8d, 0xc5,
      0xfc, 0x2c, 0x72, 0xba, 0xac, 0xea, 0x7e, 0x18, 0x53, 0x56, 0xa6, 0x83,
      0xa2, 0xce, 0x93, 0x93, 0xe7, 0x1f, 0x0f, 0xe6, 0x0f, 0x02, 0x03, 0x01,
      0x00, 0x01, 0x02, 0x81, 0x80, 0x03, 0x61, 0x89, 0x37, 0xcb, 0xf2, 0x98,
      0xa0, 0xce, 0xb4, 0xcb, 0x16, 0x13, 0xf0, 0xe6, 0xaf, 0x5c, 0xc5, 0xa7,
      0x69, 0x71, 0xca, 0xba, 0x8d, 0xe0, 0x4d, 0xdd, 0xed, 0xb8, 0x48, 0x8b,
      0x16, 0x93, 0x36, 0x95, 0xc2, 0x91, 0x40, 0x65, 0x17, 0xbd, 0x7f, 0xd6,
      0xad, 0x9e, 0x30, 0x28, 0x46, 0xe4, 0x3e, 0xcc, 0x43, 0x78, 0xf9, 0xfe,
      0x1f, 0x33, 0x23, 0x1e, 0x31, 0x12, 0x9d, 0x3c, 0xa7, 0x08, 0x82, 0x7b,
      0x7d, 0x25, 0x4e, 0x5e, 0x19, 0xa8, 0x9b, 0xed, 0x86, 0xb2, 0xcb, 0x3c,
      0xfe, 0x4e, 0xa1, 0xfa, 0x62, 0x87, 0x3a, 0x17, 0xf7, 0x60, 0xec, 0x38,
      0x29, 0xe8, 0x4f, 0x34, 0x9f, 0x76, 0x9d, 0xee, 0xa3, 0xf6, 0x85, 0x6b,
      0x84, 0x43, 0xc9, 0x1e, 0x01, 0xff, 0xfd, 0xd0, 0x29, 0x4c, 0xfa, 0x8e,
      0x57, 0x0c, 0xc0, 0x71, 0xa5, 0xbb, 0x88, 0x46, 0x29, 0x5c, 0xc0, 0x4f,
      0x01, 0x02, 0x41, 0x00, 0xf5, 0x83, 0xa4, 0x64, 0x4a, 0xf2, 0xdd, 0x8c,
      0x2c, 0xed, 0xa8, 0xd5, 0x60, 0x5a, 0xe4, 0xc7, 0xcc, 0x61, 0xcd, 0x38,
      0x42, 0x20, 0xd3, 0x82, 0x18, 0xf2, 0x35, 0x00, 0x72, 0x2d, 0xf7, 0x89,
      0x80, 0x67, 0xb5, 0x93, 0x05, 0x5f, 0xdd, 0x42, 0xba, 0x16, 0x1a, 0xea,
      0x15, 0xc6, 0xf0, 0xb8, 0x8c, 0xbc, 0xbf, 0x54, 0x9e, 0xf1, 0xc1, 0xb2,
      0xb3, 0x8b, 0xb6, 0x26, 0x02, 0x30, 0xc4, 0x81, 0x02, 0x41, 0x00, 0xc0,
      0x60, 0x62, 0x80, 0xe1, 0x22, 0x78, 0xf6, 0x9d, 0x83, 0x18, 0xeb, 0x72,
      0x45, 0xd7, 0xc8, 0x01, 0x7f, 0xa9, 0xca, 0x8f, 0x7d, 0xd6, 0xb8, 0x31,
      0x2b, 0x84, 0x7f, 0x62, 0xd9, 0xa9, 0x22, 0x17, 0x7d, 0x06, 0x35, 0x6c,
      0xf3, 0xc1, 0x94, 0x17, 0x85, 0x5a, 0xaf, 0x9c, 0x5c, 0x09, 0x3c, 0xcf,
      0x2f, 0x44, 0x9d, 0xb6, 0x52, 0x68, 0x5f, 0xf9, 0x59, 0xc8, 0x84, 0x2b,
      0x39, 0x22, 0x8f, 0x02, 0x41, 0x00, 0xb2, 0x04, 0xe2, 0x0e, 0x56, 0xca,
      0x03, 0x1a, 0xc0, 0xf9, 0x12, 0x92, 0xa5, 0x6b, 0x42, 0xb8, 0x1c, 0xda,
      0x4d, 0x93, 0x9d, 0x5f, 0x6f, 0xfd, 0xc5, 0x58, 0xda, 0x55, 0x98, 0x74,
      0xfc, 0x28, 0x17, 0x93, 0x1b, 0x75, 0x9f, 0x50, 0x03, 0x7f, 0x7e, 0xae,
      0xc8, 0x95, 0x33, 0x75, 0x2c, 0xd6, 0xa4, 0x35, 0xb8, 0x06, 0x03, 0xba,
      0x08, 0x59, 0x2b, 0x17, 0x02, 0xdc, 0x4c, 0x7a, 0x50, 0x01, 0x02, 0x41,
      0x00, 0x9d, 0xdb, 0x39, 0x59, 0x09, 0xe4, 0x30, 0xa0, 0x24, 0xf5, 0xdb,
      0x2f, 0xf0, 0x2f, 0xf1, 0x75, 0x74, 0x0d, 0x5e, 0xb5, 0x11, 0x73, 0xb0,
      0x0a, 0xaa, 0x86, 0x4c, 0x0d, 0xff, 0x7e, 0x1d, 0xb4, 0x14, 0xd4, 0x09,
      0x91, 0x33, 0x5a, 0xfd, 0xa0, 0x58, 0x80, 0x9b, 0xbe, 0x78, 0x2e, 0x69,
      0x82, 0x15, 0x7c, 0x72, 0xf0, 0x7b, 0x18, 0x39, 0xff, 0x6e, 0xeb, 0xc6,
      0x86, 0xf5, 0xb4, 0xc7, 0x6f, 0x02, 0x41, 0x00, 0x8d, 0x1a, 0x37, 0x0f,
      0x76, 0xc4, 0x82, 0xfa, 0x5c, 0xc3, 0x79, 0x35, 0x3e, 0x70, 0x8a, 0xbf,
      0x27, 0x49, 0xb0, 0x99, 0x63, 0xcb, 0x77, 0x5f, 0xa8, 0x82, 0x65, 0xf6,
      0x03, 0x52, 0x51, 0xf1, 0xae, 0x2e, 0x05, 0xb3, 0xc6, 0xa4, 0x92, 0xd1,
      0xce, 0x6c, 0x72, 0xfb, 0x21, 0xb3, 0x02, 0x87, 0xe4, 0xfd, 0x61, 0xca,
      0x00, 0x42, 0x19, 0xf0, 0xda, 0x5a, 0x53, 0xe3, 0xb1, 0xc5, 0x15, 0xf3,
  };

  std::unique_ptr<crypto::ECPrivateKey> key =
      crypto::ECPrivateKey::CreateFromPrivateKeyInfo(std::vector<uint8_t>(
          std::begin(kPrivateKeyInfo), std::end(kPrivateKeyInfo)));
  EXPECT_FALSE(key);
}

TEST(ECPrivateKeyUnitTest, LoadNSSKeyTest) {
  static const uint8_t kNSSKey[] = {
      0x30, 0x81, 0xb8, 0x30, 0x23, 0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf7,
      0x0d, 0x01, 0x0c, 0x01, 0x03, 0x30, 0x15, 0x04, 0x10, 0x3f, 0xac, 0xe9,
      0x38, 0xdb, 0x40, 0x6b, 0x26, 0x89, 0x09, 0x73, 0x18, 0x8d, 0x7f, 0x1c,
      0x82, 0x02, 0x01, 0x01, 0x04, 0x81, 0x90, 0x5e, 0x5e, 0x11, 0xef, 0xbb,
      0x7c, 0x4d, 0xec, 0xc0, 0xdc, 0xc7, 0x23, 0xd2, 0xc4, 0x77, 0xbc, 0xf4,
      0x5d, 0x59, 0x4c, 0x07, 0xc2, 0x8a, 0x26, 0xfa, 0x25, 0x1c, 0xaa, 0x42,
      0xed, 0xd0, 0xed, 0xbb, 0x5c, 0xe9, 0x13, 0x07, 0xaa, 0xdd, 0x52, 0x3c,
      0x65, 0x25, 0xbf, 0x94, 0x02, 0xaf, 0xd6, 0x97, 0xe9, 0x33, 0x00, 0x76,
      0x64, 0x4a, 0x73, 0xab, 0xfb, 0x99, 0x6e, 0x83, 0x12, 0x05, 0x86, 0x72,
      0x6c, 0xd5, 0xa4, 0xcf, 0xb1, 0xd5, 0x4d, 0x54, 0x87, 0x8b, 0x4b, 0x95,
      0x1d, 0xcd, 0xf3, 0xfe, 0xa8, 0xda, 0xe0, 0xb6, 0x72, 0x13, 0x3f, 0x2e,
      0x66, 0xe0, 0xb9, 0x2e, 0xfa, 0x69, 0x40, 0xbe, 0xd7, 0x67, 0x6e, 0x53,
      0x2b, 0x3f, 0x53, 0xe5, 0x39, 0x54, 0x77, 0xe1, 0x1d, 0xe6, 0x81, 0x92,
      0x58, 0x82, 0x14, 0xfb, 0x47, 0x85, 0x3c, 0xc3, 0xdf, 0xdd, 0xcc, 0x79,
      0x9f, 0x41, 0x83, 0x72, 0xf2, 0x0a, 0xe9, 0xe1, 0x2c, 0x12, 0xb0, 0xb0,
      0x0a, 0xb2, 0x1d, 0xca, 0x15, 0xb2, 0xca,
  };

  std::unique_ptr<crypto::ECPrivateKey> keypair_nss(
      crypto::ECPrivateKey::CreateFromEncryptedPrivateKeyInfo(
          std::vector<uint8_t>(std::begin(kNSSKey), std::end(kNSSKey))));

  EXPECT_TRUE(keypair_nss);
}

TEST(ECPrivateKeyUnitTest, LoadOpenSSLKeyTest) {
  static const uint8_t kOpenSSLKey[] = {
      0x30, 0x81, 0xb0, 0x30, 0x1b, 0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf7,
      0x0d, 0x01, 0x0c, 0x01, 0x03, 0x30, 0x0d, 0x04, 0x08, 0xb2, 0xfe, 0x68,
      0xc2, 0xea, 0x0f, 0x10, 0x9c, 0x02, 0x01, 0x01, 0x04, 0x81, 0x90, 0xe2,
      0xf6, 0x1c, 0xca, 0xad, 0x64, 0x30, 0xbf, 0x88, 0x04, 0x35, 0xe5, 0x0f,
      0x11, 0x49, 0x06, 0x01, 0x14, 0x33, 0x80, 0xa2, 0x78, 0x44, 0x5b, 0xaa,
      0x0d, 0xd7, 0x00, 0x36, 0x9d, 0x91, 0x97, 0x37, 0x20, 0x7b, 0x27, 0xc1,
      0xa0, 0xa2, 0x73, 0x06, 0x15, 0xdf, 0xc8, 0x13, 0x9b, 0xc9, 0x8c, 0x9c,
      0xce, 0x00, 0xd0, 0xc8, 0x42, 0xc1, 0xda, 0x2b, 0x07, 0x2b, 0x12, 0xa3,
      0xce, 0x10, 0x39, 0x7a, 0xf1, 0x55, 0x69, 0x8d, 0xa5, 0xc4, 0x2a, 0x00,
      0x0d, 0x94, 0xc6, 0xde, 0x6a, 0x3d, 0xb7, 0xe5, 0x6d, 0x59, 0x3e, 0x09,
      0xb5, 0xe3, 0x3e, 0xfc, 0x50, 0x56, 0xe9, 0x50, 0x42, 0x7c, 0xe7, 0xf0,
      0x19, 0xbd, 0x31, 0xa7, 0x85, 0x47, 0xb3, 0xe9, 0xb3, 0x50, 0x3c, 0xc9,
      0x32, 0x37, 0x1a, 0x93, 0x78, 0x48, 0x78, 0x82, 0xde, 0xad, 0x5c, 0xf2,
      0xcf, 0xf2, 0xbb, 0x2c, 0x44, 0x05, 0x7f, 0x4a, 0xf9, 0xb1, 0x2b, 0xdd,
      0x49, 0xf6, 0x7e, 0xd0, 0x42, 0xaa, 0x14, 0x3c, 0x24, 0x77, 0xb4,
  };
  static const uint8_t kOpenSSLPublicKey[] = {
      0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
      0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
      0x42, 0x00, 0x04, 0xb9, 0xda, 0x0d, 0x71, 0x60, 0xb3, 0x63, 0x28, 0x22,
      0x67, 0xe7, 0xe0, 0xa3, 0xf8, 0x00, 0x8e, 0x4c, 0x89, 0xed, 0x31, 0x34,
      0xf6, 0xdb, 0xc4, 0xfe, 0x0b, 0x5d, 0xe1, 0x11, 0x39, 0x49, 0xa6, 0x50,
      0xa8, 0xe3, 0x4a, 0xc0, 0x40, 0x88, 0xb8, 0x38, 0x3f, 0x56, 0xfb, 0x33,
      0x8d, 0xd4, 0x64, 0x91, 0xd6, 0x15, 0x77, 0x42, 0x27, 0xc5, 0xaa, 0x44,
      0xff, 0xab, 0x4d, 0xb5, 0x7e, 0x25, 0x3d,
  };
  static const uint8_t kOpenSSLRawPublicKey[] = {
      0xb9, 0xda, 0x0d, 0x71, 0x60, 0xb3, 0x63, 0x28, 0x22, 0x67, 0xe7,
      0xe0, 0xa3, 0xf8, 0x00, 0x8e, 0x4c, 0x89, 0xed, 0x31, 0x34, 0xf6,
      0xdb, 0xc4, 0xfe, 0x0b, 0x5d, 0xe1, 0x11, 0x39, 0x49, 0xa6, 0x50,
      0xa8, 0xe3, 0x4a, 0xc0, 0x40, 0x88, 0xb8, 0x38, 0x3f, 0x56, 0xfb,
      0x33, 0x8d, 0xd4, 0x64, 0x91, 0xd6, 0x15, 0x77, 0x42, 0x27, 0xc5,
      0xaa, 0x44, 0xff, 0xab, 0x4d, 0xb5, 0x7e, 0x25, 0x3d,
  };

  std::unique_ptr<crypto::ECPrivateKey> keypair_openssl(
      crypto::ECPrivateKey::CreateFromEncryptedPrivateKeyInfo(
          std::vector<uint8_t>(std::begin(kOpenSSLKey),
                               std::end(kOpenSSLKey))));

  EXPECT_TRUE(keypair_openssl);

  std::vector<uint8_t> public_key;
  EXPECT_TRUE(keypair_openssl->ExportPublicKey(&public_key));
  EXPECT_EQ(std::vector<uint8_t>(std::begin(kOpenSSLPublicKey),
                                 std::end(kOpenSSLPublicKey)),
            public_key);

  std::string raw_public_key;
  EXPECT_TRUE(keypair_openssl->ExportRawPublicKey(&raw_public_key));
  EXPECT_EQ(std::string(reinterpret_cast<const char*>(kOpenSSLRawPublicKey),
                        base::size(kOpenSSLRawPublicKey)),
            raw_public_key);
}

// The Android code writes out Channel IDs differently from the NSS
// implementation; the empty password is converted to "\0\0". The OpenSSL port
// should support either.
TEST(ECPrivateKeyUnitTest, LoadOldOpenSSLKeyTest) {
  static const uint8_t kOpenSSLKey[] = {
      0x30, 0x82, 0x01, 0xa1, 0x30, 0x1b, 0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86,
      0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x03, 0x30, 0x0d, 0x04, 0x08, 0x86, 0xaa,
      0xd7, 0xdf, 0x3b, 0x91, 0x97, 0x60, 0x02, 0x01, 0x01, 0x04, 0x82, 0x01,
      0x80, 0xcb, 0x2a, 0x14, 0xaa, 0x4f, 0x38, 0x4c, 0xe1, 0x49, 0x00, 0xe2,
      0x1a, 0x3a, 0x75, 0x87, 0x7e, 0x3d, 0xea, 0x4d, 0x53, 0xd4, 0x46, 0x47,
      0x23, 0x8f, 0xa1, 0x72, 0x51, 0x92, 0x86, 0x8b, 0xeb, 0x53, 0xe6, 0x6a,
      0x0a, 0x6b, 0xb6, 0xa0, 0xdc, 0x0f, 0xdc, 0x20, 0xc3, 0x45, 0x85, 0xf1,
      0x95, 0x90, 0x5c, 0xf4, 0xfa, 0xee, 0x47, 0xaf, 0x35, 0xd0, 0xd0, 0xd3,
      0x14, 0xde, 0x0d, 0xca, 0x1b, 0xd3, 0xbb, 0x20, 0xec, 0x9d, 0x6a, 0xd4,
      0xc1, 0xce, 0x60, 0x81, 0xab, 0x0c, 0x72, 0x10, 0xfa, 0x28, 0x3c, 0xac,
      0x87, 0x7b, 0x82, 0x85, 0x00, 0xb8, 0x58, 0x9c, 0x07, 0xc4, 0x7d, 0xa9,
      0xc5, 0x94, 0x95, 0xf7, 0x23, 0x93, 0x3f, 0xed, 0xef, 0x92, 0x55, 0x25,
      0x74, 0xbb, 0xd3, 0xd1, 0x67, 0x3b, 0x3d, 0x5a, 0xfe, 0x84, 0xf8, 0x97,
      0x7d, 0x7c, 0x01, 0xc7, 0xd7, 0x0d, 0xf8, 0xc3, 0x6d, 0xd6, 0xf1, 0xaa,
      0x9d, 0x1f, 0x69, 0x97, 0x45, 0x06, 0xc4, 0x1c, 0x95, 0x3c, 0xe0, 0xef,
      0x11, 0xb2, 0xb3, 0x72, 0x91, 0x9e, 0x7d, 0x0f, 0x7f, 0xc8, 0xf6, 0x64,
      0x49, 0x5e, 0x3c, 0x53, 0x37, 0x79, 0x03, 0x1c, 0x3f, 0x29, 0x6c, 0x6b,
      0xea, 0x4c, 0x35, 0x9b, 0x6d, 0x1b, 0x59, 0x43, 0x4c, 0x14, 0x47, 0x2a,
      0x36, 0x39, 0x2a, 0xd8, 0x96, 0x90, 0xdc, 0xfc, 0xd2, 0xdd, 0x23, 0x0e,
      0x2c, 0xb3, 0x83, 0xf9, 0xf2, 0xe3, 0xe6, 0x99, 0x53, 0x57, 0x33, 0xc5,
      0x5f, 0xf9, 0xfd, 0x56, 0x0b, 0x32, 0xd4, 0xf3, 0x9d, 0x5b, 0x34, 0xe5,
      0x94, 0xbf, 0xb6, 0xc0, 0xce, 0xe1, 0x73, 0x5c, 0x02, 0x7a, 0x4c, 0xed,
      0xde, 0x23, 0x38, 0x89, 0x9f, 0xcd, 0x51, 0xf3, 0x90, 0x80, 0xd3, 0x4b,
      0x83, 0xd3, 0xee, 0xf2, 0x9e, 0x35, 0x91, 0xa5, 0xa3, 0xc0, 0x5c, 0xce,
      0xdb, 0xaa, 0x70, 0x1e, 0x1d, 0xc1, 0x44, 0xea, 0x3b, 0xa7, 0x5a, 0x11,
      0xd1, 0xf3, 0xf3, 0xd0, 0xf4, 0x5a, 0xc4, 0x99, 0xaf, 0x8d, 0xe2, 0xbc,
      0xa2, 0xb9, 0x3d, 0x86, 0x5e, 0xba, 0xa0, 0xdf, 0x78, 0x81, 0x7c, 0x54,
      0x31, 0xe3, 0x98, 0xb5, 0x46, 0xcb, 0x4d, 0x26, 0x4b, 0xf8, 0xac, 0x3a,
      0x54, 0x1b, 0x77, 0x5a, 0x18, 0xa5, 0x43, 0x0e, 0x14, 0xde, 0x7b, 0xb7,
      0x4e, 0x45, 0x99, 0x03, 0xd1, 0x3d, 0x18, 0xb2, 0x36, 0x00, 0x48, 0x07,
      0x72, 0xbb, 0x4f, 0x21, 0x25, 0x3e, 0xda, 0x25, 0x24, 0x5b, 0xc8, 0xa0,
      0x28, 0xd5, 0x9b, 0x96, 0x87, 0x07, 0x77, 0x84, 0xff, 0xd7, 0xac, 0x71,
      0xf6, 0x61, 0x63, 0x0b, 0xfb, 0x42, 0xfd, 0x52, 0xf4, 0xc4, 0x35, 0x0c,
      0xc2, 0xc1, 0x55, 0x22, 0x42, 0x2f, 0x13, 0x7d, 0x93, 0x27, 0xc8, 0x11,
      0x35, 0xc5, 0xe3, 0xc5, 0xaa, 0x15, 0x3c, 0xac, 0x30, 0xbc, 0x45, 0x16,
      0xed,
  };

  std::unique_ptr<crypto::ECPrivateKey> keypair_openssl(
      crypto::ECPrivateKey::CreateFromEncryptedPrivateKeyInfo(
          std::vector<uint8_t>(std::begin(kOpenSSLKey),
                               std::end(kOpenSSLKey))));

  EXPECT_TRUE(keypair_openssl);
}
