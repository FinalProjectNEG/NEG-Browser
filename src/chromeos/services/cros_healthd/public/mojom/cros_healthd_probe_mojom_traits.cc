// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chromeos/services/cros_healthd/public/mojom/cros_healthd_probe_mojom_traits.h"

#include "base/notreached.h"

namespace em = enterprise_management;

namespace mojo {

chromeos::cros_healthd::mojom::CpuArchitectureEnum EnumTraits<
    chromeos::cros_healthd::mojom::CpuArchitectureEnum,
    em::CpuInfo::Architecture>::ToMojom(em::CpuInfo::Architecture input) {
  switch (input) {
    case em::CpuInfo::ARCHITECTURE_UNSPECIFIED:
      return chromeos::cros_healthd::mojom::CpuArchitectureEnum::kUnknown;
    case em::CpuInfo::X86_64:
      return chromeos::cros_healthd::mojom::CpuArchitectureEnum::kX86_64;
    case em::CpuInfo::AARCH64:
      return chromeos::cros_healthd::mojom::CpuArchitectureEnum::kAArch64;
    case em::CpuInfo::ARMV7L:
      return chromeos::cros_healthd::mojom::CpuArchitectureEnum::kArmv7l;
  }

  NOTREACHED();
  return chromeos::cros_healthd::mojom::CpuArchitectureEnum::kUnknown;
}

bool EnumTraits<chromeos::cros_healthd::mojom::CpuArchitectureEnum,
                em::CpuInfo::Architecture>::
    FromMojom(chromeos::cros_healthd::mojom::CpuArchitectureEnum input,
              em::CpuInfo::Architecture* out) {
  switch (input) {
    case chromeos::cros_healthd::mojom::CpuArchitectureEnum::kUnknown:
      *out = em::CpuInfo::ARCHITECTURE_UNSPECIFIED;
      return true;
    case chromeos::cros_healthd::mojom::CpuArchitectureEnum::kX86_64:
      *out = em::CpuInfo::X86_64;
      return true;
    case chromeos::cros_healthd::mojom::CpuArchitectureEnum::kAArch64:
      *out = em::CpuInfo::AARCH64;
      return true;
    case chromeos::cros_healthd::mojom::CpuArchitectureEnum::kArmv7l:
      *out = em::CpuInfo::ARMV7L;
      return true;
  }

  NOTREACHED();
  return false;
}

}  // namespace mojo
