// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_DEVTOOLS_PROTOCOL_DEVTOOLS_DOMAIN_HANDLER_H_
#define CONTENT_BROWSER_DEVTOOLS_PROTOCOL_DEVTOOLS_DOMAIN_HANDLER_H_

#include "content/browser/devtools/protocol/forward.h"
#include "content/browser/devtools/shared_worker_devtools_agent_host.h"

namespace content {

class RenderFrameHostImpl;
class DevToolsSession;

namespace protocol {

class DevToolsDomainHandler {
 public:
  explicit DevToolsDomainHandler(const std::string& name);
  virtual ~DevToolsDomainHandler();

  virtual void SetRenderer(int process_host_id,
                           RenderFrameHostImpl* frame_host);
  virtual void Wire(UberDispatcher* dispatcher);
  void SetSession(DevToolsSession* session);
  virtual Response Disable();

  const std::string& name() const;

 protected:
  DevToolsSession* session();

 private:
  std::string name_;
  DevToolsSession* session_;

  DISALLOW_COPY_AND_ASSIGN(DevToolsDomainHandler);
};

}  // namespace protocol
}  // namespace content

#endif  // CONTENT_BROWSER_DEVTOOLS_PROTOCOL_DEVTOOLS_DOMAIN_HANDLER_H_
