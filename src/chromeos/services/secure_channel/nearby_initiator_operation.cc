// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chromeos/services/secure_channel/nearby_initiator_operation.h"

#include "base/bind.h"
#include "base/memory/ptr_util.h"
#include "chromeos/services/secure_channel/authenticated_channel.h"
#include "chromeos/services/secure_channel/nearby_connection_manager.h"

namespace chromeos {

namespace secure_channel {

// static
NearbyInitiatorOperation::Factory*
    NearbyInitiatorOperation::Factory::test_factory_ = nullptr;

// static
std::unique_ptr<ConnectToDeviceOperation<NearbyInitiatorFailureType>>
NearbyInitiatorOperation::Factory::Create(
    NearbyConnectionManager* nearby_connection_manager,
    ConnectToDeviceOperation<
        NearbyInitiatorFailureType>::ConnectionSuccessCallback success_callback,
    const ConnectToDeviceOperation<
        NearbyInitiatorFailureType>::ConnectionFailedCallback& failure_callback,
    const DeviceIdPair& device_id_pair,
    ConnectionPriority connection_priority,
    scoped_refptr<base::TaskRunner> task_runner) {
  if (test_factory_) {
    return test_factory_->CreateInstance(
        nearby_connection_manager, std::move(success_callback),
        std::move(failure_callback), device_id_pair, connection_priority,
        std::move(task_runner));
  }

  return base::WrapUnique(new NearbyInitiatorOperation(
      nearby_connection_manager, std::move(success_callback),
      std::move(failure_callback), device_id_pair, connection_priority,
      std::move(task_runner)));
}

// static
void NearbyInitiatorOperation::Factory::SetFactoryForTesting(
    Factory* test_factory) {
  test_factory_ = test_factory;
}

NearbyInitiatorOperation::Factory::~Factory() = default;

NearbyInitiatorOperation::NearbyInitiatorOperation(
    NearbyConnectionManager* nearby_connection_manager,
    ConnectToDeviceOperation<
        NearbyInitiatorFailureType>::ConnectionSuccessCallback success_callback,
    const ConnectToDeviceOperation<
        NearbyInitiatorFailureType>::ConnectionFailedCallback& failure_callback,
    const DeviceIdPair& device_id_pair,
    ConnectionPriority connection_priority,
    scoped_refptr<base::TaskRunner> task_runner)
    : ConnectToDeviceOperationBase<NearbyInitiatorFailureType>(
          std::move(success_callback),
          std::move(failure_callback),
          device_id_pair,
          connection_priority,
          task_runner),
      nearby_connection_manager_(nearby_connection_manager) {}

NearbyInitiatorOperation::~NearbyInitiatorOperation() = default;

void NearbyInitiatorOperation::PerformAttemptConnectionToDevice(
    ConnectionPriority connection_priority) {
  nearby_connection_manager_->AttemptNearbyInitiatorConnection(
      device_id_pair(),
      base::BindOnce(&NearbyInitiatorOperation::OnSuccessfulConnection,
                     weak_ptr_factory_.GetWeakPtr()),
      base::BindRepeating(&NearbyInitiatorOperation::OnConnectionFailure,
                          weak_ptr_factory_.GetWeakPtr()));
}

void NearbyInitiatorOperation::PerformCancellation() {
  nearby_connection_manager_->CancelNearbyInitiatorConnectionAttempt(
      device_id_pair());
}

void NearbyInitiatorOperation::PerformUpdateConnectionPriority(
    ConnectionPriority connection_priority) {
  // Note: Nearby Connections are not performed differently based on the
  // connection priority, so this function is intentionally empty.
}

void NearbyInitiatorOperation::OnSuccessfulConnection(
    std::unique_ptr<AuthenticatedChannel> authenticated_channel) {
  OnSuccessfulConnectionAttempt(std::move(authenticated_channel));
}

void NearbyInitiatorOperation::OnConnectionFailure(
    NearbyInitiatorFailureType failure_type) {
  OnFailedConnectionAttempt(failure_type);
}

}  // namespace secure_channel

}  // namespace chromeos
