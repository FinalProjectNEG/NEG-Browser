// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/privacy_budget/identifiability_digest_helpers.h"

#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "third_party/blink/renderer/platform/wtf/text/string_hash.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

// Arbitrary value chosen to represent null strings.
constexpr uint64_t kNullStringDigest = 6554271438612835841L;

IdentifiableToken IdentifiabilityBenignStringToken(const String& in) {
  if (in.IsNull())
    return kNullStringDigest;

  // Return the precomputed hash for the string. This makes this method O(1)
  // instead of O(n), at the cost of only using the lower 32 bits of the hash.
  return IdentifiableToken(StringHash::GetHash(in));
}

IdentifiableToken IdentifiabilitySensitiveStringToken(const String& in) {
  if (in.IsNull())
    return IdentifiableToken(kNullStringDigest);

  // Take the precomputed 32-bit hash, and xor the top and bottom halves to
  // produce a 16-bit hash.
  const uint32_t original_hash = StringHash::GetHash(in);
  return IdentifiableToken(((original_hash & 0xFFFF0000) >> 16) ^
                           (original_hash & 0xFFFF));
}

IdentifiableToken IdentifiabilityBenignCaseFoldingStringToken(
    const String& in) {
  if (in.IsNull())
    return kNullStringDigest;

  return IdentifiableToken(CaseFoldingHash::GetHash(in));
}

IdentifiableToken IdentifiabilitySensitiveCaseFoldingStringToken(
    const String& in) {
  if (in.IsNull())
    return IdentifiableToken(kNullStringDigest);

  // Take the 32-bit hash, and xor the top and bottom halves to produce a 16-bit
  // hash.
  const uint32_t original_hash = CaseFoldingHash::GetHash(in);
  return IdentifiableToken(((original_hash & 0xFFFF0000) >> 16) ^
                           (original_hash & 0xFFFF));
}

}  // namespace blink
