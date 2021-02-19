// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/web_test/renderer/fake_subresource_filter.h"

#include <algorithm>

#include "base/strings/string_util.h"
#include "third_party/blink/public/platform/web_url.h"
#include "url/gurl.h"

namespace content {

FakeSubresourceFilter::FakeSubresourceFilter(
    std::vector<std::string> disallowed_path_suffixes,
    bool block_subresources)
    : disallowed_path_suffixes_(std::move(disallowed_path_suffixes)),
      block_subresources_(block_subresources) {}

FakeSubresourceFilter::~FakeSubresourceFilter() = default;

blink::WebDocumentSubresourceFilter::LoadPolicy
FakeSubresourceFilter::GetLoadPolicy(const blink::WebURL& resource_url,
                                     blink::mojom::RequestContextType) {
  return GetLoadPolicyImpl(resource_url);
}

blink::WebDocumentSubresourceFilter::LoadPolicy
FakeSubresourceFilter::GetLoadPolicyForWebSocketConnect(
    const blink::WebURL& url) {
  return GetLoadPolicyImpl(url);
}

blink::WebDocumentSubresourceFilter::LoadPolicy
FakeSubresourceFilter::GetLoadPolicyImpl(const blink::WebURL& url) {
  GURL gurl(url);
  base::StringPiece path(gurl.path_piece());

  auto it = std::find_if(
      disallowed_path_suffixes_.begin(), disallowed_path_suffixes_.end(),
      [&path](const std::string& suffix) {
        return base::EndsWith(path, suffix, base::CompareCase::SENSITIVE);
      });
  // Allows things not listed in |disallowed_path_suffixes_|.
  if (it == disallowed_path_suffixes_.end())
    return kAllow;
  // Disallows everything in |disallowed_path_suffixes_| only if
  // |block_subresources| is true.
  if (block_subresources_)
    return kDisallow;
  return kWouldDisallow;
}

void FakeSubresourceFilter::ReportDisallowedLoad() {}

bool FakeSubresourceFilter::ShouldLogToConsole() {
  return true;
}

}  // namespace content
