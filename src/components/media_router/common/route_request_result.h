// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_MEDIA_ROUTER_COMMON_ROUTE_REQUEST_RESULT_H_
#define COMPONENTS_MEDIA_ROUTER_COMMON_ROUTE_REQUEST_RESULT_H_

#include <memory>
#include <string>

#include "base/macros.h"
#include "url/gurl.h"

namespace media_router {

class MediaRoute;

// Holds the result of a successful or failed route request.
// On success:
// |route|: The route created or joined.
// |presentation_id|:
//     The presentation ID of the route created or joined. In the case of
//     |CreateRoute()|, the ID is generated by MediaRouter and is guaranteed to
//     be unique.
// |error|: Empty string.
// |result_code|: RouteRequestResult::OK
// On failure:
// |route|: nullptr
// |presentation_id|: Empty string.
// |error|: Non-empty string describing the error.
// |result_code|: A value from RouteRequestResult describing the error.
class RouteRequestResult {
 public:
  // Keep in sync with:
  // - RouteRequestResultCode in media_router.mojom
  // - MediaRouteProviderResult enum in tools/metrics/histograms/enums.xml
  // - media_router_mojom_traits.h
  enum ResultCode {
    UNKNOWN_ERROR = 0,
    OK = 1,
    TIMED_OUT = 2,
    ROUTE_NOT_FOUND = 3,
    SINK_NOT_FOUND = 4,
    INVALID_ORIGIN = 5,
    OFF_THE_RECORD_MISMATCH = 6,
    NO_SUPPORTED_PROVIDER = 7,
    CANCELLED = 8,
    ROUTE_ALREADY_EXISTS = 9,
    DESKTOP_PICKER_FAILED = 10,
    // New values must be added here.

    TOTAL_COUNT = 11  // The total number of values.
  };

  static std::unique_ptr<RouteRequestResult> FromSuccess(
      const MediaRoute& route,
      const std::string& presentation_id);
  static std::unique_ptr<RouteRequestResult> FromError(const std::string& error,
                                                       ResultCode result_code);
  RouteRequestResult(std::unique_ptr<MediaRoute> route,
                     const std::string& presentation_id,
                     const std::string& error,
                     ResultCode result_code);

  ~RouteRequestResult();

  // Note the caller does not own the returned MediaRoute. The caller must
  // create a copy if they wish to use it after this object is destroyed.
  const MediaRoute* route() const { return route_.get(); }
  std::string presentation_id() const { return presentation_id_; }
  GURL presentation_url() const { return presentation_url_; }
  std::string error() const { return error_; }
  ResultCode result_code() const { return result_code_; }

 private:
  std::unique_ptr<MediaRoute> route_;
  std::string presentation_id_;
  GURL presentation_url_;
  std::string error_;
  ResultCode result_code_;

  DISALLOW_COPY_AND_ASSIGN(RouteRequestResult);
};

}  // namespace media_router

#endif  // COMPONENTS_MEDIA_ROUTER_COMMON_ROUTE_REQUEST_RESULT_H_
