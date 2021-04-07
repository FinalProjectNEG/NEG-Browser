// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/content_settings/core/browser/private_network_settings.h"

#include "base/logging.h"
#include "components/content_settings/core/browser/host_content_settings_map.h"
#include "components/content_settings/core/common/content_settings_types.h"

namespace content_settings {

// There are two inputs that go into the INSECURE_PRIVATE_NETWORK content
// setting for a URL:
//
//  - the blanket InsecurePrivateNetworkRequestsAllowed enterprise policy:
//    - if this policy is set to true, then the content setting is always ALLOW
//    - otherwise, the content setting is BLOCK by default
//  - the InsecurePrivateNetworkRequestsAllowedForUrls enterprise policy:
//    - if an origin is listed in this policy, then the content setting is
//      always ALLOW for URLs of that origin
//
bool ShouldAllowInsecurePrivateNetworkRequests(
    const HostContentSettingsMap* map,
    const GURL& url) {
  const std::string unused_resource_identifier;
  const ContentSetting setting = map->GetContentSetting(
      url, url, ContentSettingsType::INSECURE_PRIVATE_NETWORK,
      unused_resource_identifier);

  switch (setting) {
    case CONTENT_SETTING_ALLOW:
      return true;
    case CONTENT_SETTING_BLOCK:
      return false;
    default:
      NOTREACHED()
          << "Invalid content setting for insecure private network requests: "
          << setting;
      return false;
  }
}

}  // namespace content_settings
