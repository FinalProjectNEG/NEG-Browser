// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/optimization_guide/memory_hint.h"

namespace optimization_guide {

MemoryHint::MemoryHint(const base::Optional<base::Time>& expiry_time,
                       std::unique_ptr<proto::Hint> hint)
    : expiry_time_(expiry_time), hint_(std::move(hint)) {}

MemoryHint::MemoryHint(const base::Time expiry_time, proto::Hint&& hint)
    : expiry_time_(base::Optional<base::Time>(expiry_time)),
      hint_(std::make_unique<proto::Hint>(hint)) {}

MemoryHint::~MemoryHint() = default;

}  // namespace optimization_guide
