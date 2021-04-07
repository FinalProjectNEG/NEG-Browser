// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_PUBLIC_BROWSER_GPU_UTILS_H_
#define CONTENT_PUBLIC_BROWSER_GPU_UTILS_H_

#include "base/callback_forward.h"
#include "base/clang_profiling_buildflags.h"
#include "content/common/content_export.h"
#include "gpu/config/gpu_preferences.h"

namespace gpu {
class GpuChannelEstablishFactory;
}

namespace content {

CONTENT_EXPORT const gpu::GpuPreferences GetGpuPreferencesFromCommandLine();

CONTENT_EXPORT void StopGpuProcess(base::OnceClosure callback);

// Kills the GPU process with a normal termination status.
// TODO(crbug.com/1095977): Combine with StopGpuProcess
CONTENT_EXPORT void KillGpuProcess();

CONTENT_EXPORT gpu::GpuChannelEstablishFactory* GetGpuChannelEstablishFactory();

#if BUILDFLAG(CLANG_PROFILING_INSIDE_SANDBOX)
CONTENT_EXPORT void DumpGpuProfilingData(base::OnceClosure callback);
#endif

}  // namespace content

#endif  // CONTENT_PUBLIC_BROWSER_GPU_UTILS_H_
