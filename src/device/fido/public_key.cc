// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "device/fido/public_key.h"

#include <vector>
#include "base/containers/span.h"
#include "base/optional.h"
#include "device/fido/fido_parsing_utils.h"

namespace device {

PublicKey::PublicKey(int32_t in_algorithm,
                     base::span<const uint8_t> in_cose_key_bytes,
                     base::Optional<std::vector<uint8_t>> in_der_bytes)
    : algorithm(in_algorithm),
      cose_key_bytes(fido_parsing_utils::Materialize(in_cose_key_bytes)),
      der_bytes(std::move(in_der_bytes)) {}

PublicKey::~PublicKey() = default;

}  // namespace device
