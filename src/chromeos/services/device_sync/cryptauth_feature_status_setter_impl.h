// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROMEOS_SERVICES_DEVICE_SYNC_CRYPTAUTH_FEATURE_STATUS_SETTER_IMPL_H_
#define CHROMEOS_SERVICES_DEVICE_SYNC_CRYPTAUTH_FEATURE_STATUS_SETTER_IMPL_H_

#include <memory>
#include <ostream>
#include <string>

#include "base/callback.h"
#include "base/containers/queue.h"
#include "base/macros.h"
#include "base/optional.h"
#include "base/time/time.h"
#include "base/timer/timer.h"
#include "chromeos/components/multidevice/software_feature.h"
#include "chromeos/services/device_sync/cryptauth_feature_status_setter.h"
#include "chromeos/services/device_sync/feature_status_change.h"
#include "chromeos/services/device_sync/network_request_error.h"
#include "chromeos/services/device_sync/proto/cryptauth_devicesync.pb.h"

namespace chromeos {

namespace device_sync {

class CryptAuthClient;
class CryptAuthClientFactory;

// An implementation of CryptAuthFeatureStatusSetter, using instances of
// CryptAuthClient to make the BatchSetFeatureStatuses API calls to CryptAuth.
// The requests made via SetFeatureStatus() are queued and processed
// sequentially. This implementation handles timeouts internally, so a callback
// passed to SetFeatureStatus() is always guaranteed to be invoked.
class CryptAuthFeatureStatusSetterImpl : public CryptAuthFeatureStatusSetter {
 public:
  class Factory {
   public:
    static std::unique_ptr<CryptAuthFeatureStatusSetter> Create(
        const std::string& instance_id,
        const std::string& instance_id_token,
        CryptAuthClientFactory* client_factory,
        std::unique_ptr<base::OneShotTimer> timer =
            std::make_unique<base::OneShotTimer>());

    static void SetFactoryForTesting(Factory* test_factory);

   protected:
    virtual ~Factory();
    virtual std::unique_ptr<CryptAuthFeatureStatusSetter> CreateInstance(
        const std::string& instance_id,
        const std::string& instance_id_token,
        CryptAuthClientFactory* client_factory,
        std::unique_ptr<base::OneShotTimer> timer) = 0;

   private:
    static Factory* test_factory_;
  };

  ~CryptAuthFeatureStatusSetterImpl() override;

 private:
  enum class State { kIdle, kWaitingForBatchSetFeatureStatusesResponse };

  friend std::ostream& operator<<(std::ostream& stream, const State& state);

  static base::Optional<base::TimeDelta> GetTimeoutForState(State state);

  struct Request {
    Request(const std::string& device_id,
            multidevice::SoftwareFeature feature,
            FeatureStatusChange status_change,
            base::OnceClosure success_callback,
            base::OnceCallback<void(NetworkRequestError)> error_callback);

    Request(Request&& request);

    ~Request();

    const std::string device_id;
    const multidevice::SoftwareFeature feature;
    const FeatureStatusChange status_change;
    base::OnceClosure success_callback;
    base::OnceCallback<void(NetworkRequestError)> error_callback;
  };

  CryptAuthFeatureStatusSetterImpl(const std::string& instance_id,
                                   const std::string& instance_id_token,
                                   CryptAuthClientFactory* client_factory,
                                   std::unique_ptr<base::OneShotTimer> timer);

  // CryptAuthFeatureStatusSetter:
  void SetFeatureStatus(
      const std::string& device_id,
      multidevice::SoftwareFeature feature,
      FeatureStatusChange status_change,
      base::OnceClosure success_callback,
      base::OnceCallback<void(NetworkRequestError)> error_callback) override;

  void SetState(State state);
  void OnTimeout();

  void ProcessRequestQueue();
  void OnBatchSetFeatureStatusesSuccess(
      const cryptauthv2::BatchSetFeatureStatusesResponse& response);
  void OnBatchSetFeatureStatusesFailure(NetworkRequestError error);
  void FinishAttempt(base::Optional<NetworkRequestError> error);

  State state_ = State::kIdle;
  base::TimeTicks last_state_change_timestamp_;
  base::queue<Request> pending_requests_;

  std::string instance_id_;
  std::string instance_id_token_;
  CryptAuthClientFactory* client_factory_ = nullptr;
  std::unique_ptr<CryptAuthClient> cryptauth_client_;
  std::unique_ptr<base::OneShotTimer> timer_;
  base::WeakPtrFactory<CryptAuthFeatureStatusSetterImpl> weak_ptr_factory_{
      this};

  DISALLOW_COPY_AND_ASSIGN(CryptAuthFeatureStatusSetterImpl);
};

}  // namespace device_sync

}  // namespace chromeos

#endif  //  CHROMEOS_SERVICES_DEVICE_SYNC_CRYPTAUTH_FEATURE_STATUS_SETTER_IMPL_H_
