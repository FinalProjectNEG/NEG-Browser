// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/media/router/providers/cast/cast_media_route_provider_metrics.h"

#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/time/time.h"

using cast_channel::ReceiverAppType;

namespace media_router {

void RecordAppAvailabilityResult(cast_channel::GetAppAvailabilityResult result,
                                 base::TimeDelta duration) {
  if (result == cast_channel::GetAppAvailabilityResult::kUnknown)
    UMA_HISTOGRAM_TIMES(kHistogramAppAvailabilityFailure, duration);
  else
    UMA_HISTOGRAM_TIMES(kHistogramAppAvailabilitySuccess, duration);
}

void RecordLaunchSessionRequestSupportedAppTypes(
    std::vector<ReceiverAppType> types) {
  DCHECK(base::Contains(types, ReceiverAppType::kWeb));
  bool has_atv = false;
  for (ReceiverAppType type : types) {
    switch (type) {
      case ReceiverAppType::kAndroidTv:
        has_atv = true;
        break;
      case ReceiverAppType::kWeb:
      case ReceiverAppType::kOther:
        break;
    }
  }
  base::UmaHistogramEnumeration(kHistogramCastSupportedAppTypes,
                                has_atv ? ReceiverAppTypeSet::kAndroidTvAndWeb
                                        : ReceiverAppTypeSet::kWeb);
}

void RecordLaunchSessionResponseAppType(const base::Value* app_type) {
  if (!app_type) {
    return;
  }
  base::Optional<ReceiverAppType> type =
      cast_util::StringToEnum<ReceiverAppType>(app_type->GetString());
  if (type) {
    base::UmaHistogramEnumeration(kHistogramCastAppType, *type);
  } else {
    base::UmaHistogramEnumeration(kHistogramCastAppType,
                                  cast_channel::ReceiverAppType::kOther);
  }
}

}  // namespace media_router
