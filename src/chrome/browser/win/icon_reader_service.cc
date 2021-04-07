// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/win/icon_reader_service.h"

#include "chrome/browser/service_sandbox_type.h"
#include "chrome/grit/generated_resources.h"
#include "content/public/browser/service_process_host.h"

mojo::Remote<chrome::mojom::UtilReadIcon> LaunchIconReaderInstance() {
  return content::ServiceProcessHost::Launch<chrome::mojom::UtilReadIcon>(
      content::ServiceProcessHost::Options()
          .WithDisplayName(IDS_UTILITY_PROCESS_UTILITY_WIN_NAME)
          .Pass());
}
