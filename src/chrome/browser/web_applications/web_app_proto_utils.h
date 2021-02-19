// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_WEB_APPLICATIONS_WEB_APP_PROTO_UTILS_H_
#define CHROME_BROWSER_WEB_APPLICATIONS_WEB_APP_PROTO_UTILS_H_

#include <vector>

#include "base/optional.h"
#include "chrome/browser/web_applications/proto/web_app.pb.h"
#include "chrome/browser/web_applications/web_app.h"
#include "components/sync/protocol/web_app_specifics.pb.h"

namespace web_app {

enum class RunOnOsLoginMode;

using RepeatedIconInfosProto =
    const ::google::protobuf::RepeatedPtrField<::sync_pb::WebAppIconInfo>;

base::Optional<std::vector<WebApplicationIconInfo>> ParseWebAppIconInfos(
    const char* container_name_for_logging,
    RepeatedIconInfosProto icon_infos_proto);

// Use the given |app| to populate a |WebAppSpecifics| sync proto.
sync_pb::WebAppSpecifics WebAppToSyncProto(const WebApp& app);

// Use the given |icon_info| to populate a |WebAppIconInfo| sync proto.
sync_pb::WebAppIconInfo WebAppIconInfoToSyncProto(
    const WebApplicationIconInfo& icon_info);

base::Optional<WebApp::SyncFallbackData> ParseSyncFallbackDataStruct(
    const sync_pb::WebAppSpecifics& sync_proto);

::sync_pb::WebAppSpecifics::UserDisplayMode ToWebAppSpecificsUserDisplayMode(
    DisplayMode user_display_mode);

RunOnOsLoginMode ToRunOnOsLoginMode(WebAppProto::RunOnOsLoginMode mode);

WebAppProto::RunOnOsLoginMode ToWebAppProtoRunOnOsLoginMode(
    RunOnOsLoginMode mode);

}  // namespace web_app

#endif  // CHROME_BROWSER_WEB_APPLICATIONS_WEB_APP_PROTO_UTILS_H_
