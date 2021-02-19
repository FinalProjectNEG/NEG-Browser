// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_COMMON_ZYGOTE_ZYGOTE_HANDLE_IMPL_LINUX_H_
#define CONTENT_COMMON_ZYGOTE_ZYGOTE_HANDLE_IMPL_LINUX_H_

#include "content/public/common/zygote/zygote_handle.h"

namespace content {

using ZygoteLaunchCallback =
    base::OnceCallback<pid_t(base::CommandLine*, base::ScopedFD*)>;

// Allocates and initializes the global generic zygote process, and returns the
// ZygoteHandle used to communicate with it. |launch_cb| is a callback that
// should actually launch the process, after adding additional command line
// switches to the ones composed by this function. It returns the pid created,
// and provides a control fd for it.
CONTENT_EXPORT
ZygoteHandle CreateGenericZygote(ZygoteLaunchCallback launch_cb);

// Similar to the above but for creating an unsandboxed zygote from which
// processes which need non-generic sandboxes can be derived.
CONTENT_EXPORT
ZygoteHandle CreateUnsandboxedZygote(ZygoteLaunchCallback launch_cb);
CONTENT_EXPORT ZygoteHandle GetUnsandboxedZygote();

}  // namespace content

#endif  // CONTENT_COMMON_ZYGOTE_ZYGOTE_HANDLE_IMPL_LINUX_H_
