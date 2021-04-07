// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_NEARBY_SHARING_WEBRTC_REQUEST_BUILDER_H_
#define CHROME_BROWSER_NEARBY_SHARING_WEBRTC_REQUEST_BUILDER_H_

#include <string>

namespace chrome_browser_nearby_sharing_instantmessaging {

class SendMessageExpressRequest;
class ReceiveMessagesExpressRequest;

}  // namespace chrome_browser_nearby_sharing_instantmessaging

chrome_browser_nearby_sharing_instantmessaging::SendMessageExpressRequest
BuildSendRequest(const std::string& self_id, const std::string& peer_id);

chrome_browser_nearby_sharing_instantmessaging::ReceiveMessagesExpressRequest
BuildReceiveRequest(const std::string& self_id);

#endif  // CHROME_BROWSER_NEARBY_SHARING_WEBRTC_REQUEST_BUILDER_H_
