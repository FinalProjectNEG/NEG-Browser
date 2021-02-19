// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/extensions/blocklist_check.h"

#include "base/bind.h"
#include "chrome/browser/extensions/blocklist.h"
#include "extensions/common/extension.h"

namespace extensions {

BlocklistCheck::BlocklistCheck(Blocklist* blocklist,
                               scoped_refptr<const Extension> extension)
    : PreloadCheck(extension), blocklist_(blocklist) {}

BlocklistCheck::~BlocklistCheck() {}

void BlocklistCheck::Start(ResultCallback callback) {
  callback_ = std::move(callback);

  blocklist_->IsBlocklisted(
      extension()->id(),
      base::Bind(&BlocklistCheck::OnBlocklistedStateRetrieved,
                 weak_ptr_factory_.GetWeakPtr()));
}

void BlocklistCheck::OnBlocklistedStateRetrieved(
    BlocklistState blocklist_state) {
  Errors errors;
  if (blocklist_state == BlocklistState::BLOCKLISTED_MALWARE)
    errors.insert(PreloadCheck::BLOCKLISTED_ID);
  else if (blocklist_state == BlocklistState::BLOCKLISTED_UNKNOWN)
    errors.insert(PreloadCheck::BLOCKLISTED_UNKNOWN);
  std::move(callback_).Run(errors);
}

}  // namespace extensions
