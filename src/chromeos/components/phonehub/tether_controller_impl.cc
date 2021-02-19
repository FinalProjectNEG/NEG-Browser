// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chromeos/components/phonehub/tether_controller_impl.h"

#include "chromeos/components/multidevice/logging/logging.h"
#include "chromeos/services/network_config/in_process_instance.h"

namespace chromeos {
namespace phonehub {
namespace {

using multidevice_setup::MultiDeviceSetupClient;
using multidevice_setup::mojom::Feature;
using multidevice_setup::mojom::FeatureState;

using network_config::mojom::ConnectionStateType;
using network_config::mojom::DeviceStatePropertiesPtr;
using network_config::mojom::FilterType;
using network_config::mojom::NetworkType;
using network_config::mojom::StartConnectResult;

}  // namespace

TetherControllerImpl::TetherNetworkConnector::TetherNetworkConnector() {
  chromeos::network_config::BindToInProcessInstance(
      cros_network_config_.BindNewPipeAndPassReceiver());
}

TetherControllerImpl::TetherNetworkConnector::~TetherNetworkConnector() =
    default;

void TetherControllerImpl::TetherNetworkConnector::StartConnect(
    const std::string& guid,
    StartConnectCallback callback) {
  cros_network_config_->StartConnect(guid, std::move(callback));
}

void TetherControllerImpl::TetherNetworkConnector::StartDisconnect(
    const std::string& guid,
    StartDisconnectCallback callback) {
  cros_network_config_->StartDisconnect(guid, std::move(callback));
}

TetherControllerImpl::TetherControllerImpl(
    MultiDeviceSetupClient* multidevice_setup_client)
    : TetherControllerImpl(
          multidevice_setup_client,
          std::make_unique<TetherControllerImpl::TetherNetworkConnector>()) {}

TetherControllerImpl::TetherControllerImpl(
    MultiDeviceSetupClient* multidevice_setup_client,
    std::unique_ptr<TetherControllerImpl::TetherNetworkConnector> connector)
    : multidevice_setup_client_(multidevice_setup_client),
      connector_(std::move(connector)) {
  // Receive updates when devices (e.g., Tether, Ethernet, Wi-Fi) go on/offline
  // This class only cares about Tether devices.
  chromeos::network_config::BindToInProcessInstance(
      cros_network_config_.BindNewPipeAndPassReceiver());
  cros_network_config_->AddObserver(receiver_.BindNewPipeAndPassRemote());

  multidevice_setup_client_->AddObserver(this);

  // Compute current status.
  status_ = ComputeStatus();

  // Load the current tether network if it exists.
  FetchVisibleTetherNetwork();
}

TetherControllerImpl::~TetherControllerImpl() {
  multidevice_setup_client_->RemoveObserver(this);
}

TetherController::Status TetherControllerImpl::GetStatus() const {
  return status_;
}

void TetherControllerImpl::ScanForAvailableConnection() {
  if (status_ != Status::kConnectionUnavailable) {
    PA_LOG(WARNING) << "Received request to scan for available connection, but "
                    << "a scan cannot be performed because the current status "
                    << "is " << status_;
    return;
  }

  PA_LOG(INFO) << "Scanning for available connection.";
  cros_network_config_->RequestNetworkScan(NetworkType::kTether);
}

void TetherControllerImpl::AttemptConnection() {
  if (status_ != Status::kConnectionUnavailable &&
      status_ != Status::kConnectionAvailable) {
    PA_LOG(WARNING) << "Received request to attempt a connection, but a "
                    << "connection cannot be attempted because the current "
                    << "status is " << status_;
    return;
  }

  PA_LOG(INFO) << "Attempting connection; current status is " << status_;

  FeatureState feature_state =
      multidevice_setup_client_->GetFeatureState(Feature::kInstantTethering);

  if (feature_state == FeatureState::kEnabledByUser) {
    PerformConnectionAttempt();
    return;
  }

  // The Tethering feature was disabled and must be enabled first, before a
  // connection attempt can be made.
  DCHECK(feature_state == FeatureState::kDisabledByUser);
  AttemptTurningOnTethering();
}

void TetherControllerImpl::AttemptTurningOnTethering() {
  SetConnectDisconnectStatus(
      ConnectDisconnectStatus::kTurningOnInstantTethering);
  multidevice_setup_client_->SetFeatureEnabledState(
      Feature::kInstantTethering,
      /*enabled=*/true,
      /*auth_token=*/base::nullopt,
      base::BindOnce(&TetherControllerImpl::OnSetFeatureEnabled,
                     weak_ptr_factory_.GetWeakPtr()));
}

void TetherControllerImpl::OnSetFeatureEnabled(bool success) {
  if (connect_disconnect_status_ !=
      ConnectDisconnectStatus::kTurningOnInstantTethering) {
    return;
  }

  if (success) {
    PerformConnectionAttempt();
    return;
  }

  PA_LOG(WARNING) << "Failed to enable InstantTethering";
  SetConnectDisconnectStatus(ConnectDisconnectStatus::kIdle);
}

void TetherControllerImpl::OnFeatureStatesChanged(
    const MultiDeviceSetupClient::FeatureStatesMap& feature_states_map) {
  FeatureState feature_state =
      multidevice_setup_client_->GetFeatureState(Feature::kInstantTethering);

  // The |connect_disconnect_status_| should always be
  // ConnectDisconnectStatus::kIdle if the |feature_state| is anything other
  // than |FeatureState::kEnabledByUser|. A |feature_status| other than
  // |FeatureState::kEnabledByUser| would indicate that Instant Tethering became
  // disabled or disallowed.
  if (feature_state != FeatureState::kEnabledByUser) {
    SetConnectDisconnectStatus(ConnectDisconnectStatus::kIdle);
  } else if (connect_disconnect_status_ !=
             ConnectDisconnectStatus::kTurningOnInstantTethering) {
    UpdateStatus();
  }
}

void TetherControllerImpl::PerformConnectionAttempt() {
  if (!tether_network_.is_null()) {
    StartConnect();
    return;
  }
  SetConnectDisconnectStatus(
      ConnectDisconnectStatus::kScanningForEligiblePhone);
  cros_network_config_->RequestNetworkScan(NetworkType::kTether);
}

void TetherControllerImpl::StartConnect() {
  DCHECK(!tether_network_.is_null());
  SetConnectDisconnectStatus(
      ConnectDisconnectStatus::kConnectingToEligiblePhone);
  connector_->StartConnect(
      tether_network_->guid,
      base::BindOnce(&TetherControllerImpl::OnStartConnectCompleted,
                     weak_ptr_factory_.GetWeakPtr()));
}

void TetherControllerImpl::OnStartConnectCompleted(StartConnectResult result,
                                                   const std::string& message) {
  if (result != StartConnectResult::kSuccess) {
    PA_LOG(WARNING) << "Start connect failed with result " << result
                    << " and message " << message;
  }

  if (connect_disconnect_status_ !=
      ConnectDisconnectStatus::kConnectingToEligiblePhone) {
    return;
  }

  // Note that OnVisibleTetherNetworkFetched() has not called
  // SetConnectDisconnectStatus() with kIdle at this point, so this should go
  // ahead and do it.
  SetConnectDisconnectStatus(ConnectDisconnectStatus::kIdle);
}

void TetherControllerImpl::Disconnect() {
  if (status_ != Status::kConnecting && status_ != Status::kConnected) {
    PA_LOG(WARNING) << "Received request to disconnect, but no connection or "
                    << "connection attempt is in progress. Current status is "
                    << status_;
    return;
  }

  // If |status_| is Status::kConnecting, a tether network may not be available
  // yet e.g this class may be in the process of enabling Instant Tethering.
  if (tether_network_.is_null()) {
    SetConnectDisconnectStatus(ConnectDisconnectStatus::kIdle);
    return;
  }

  PA_LOG(INFO) << "Attempting disconnection; current status is " << status_;
  SetConnectDisconnectStatus(ConnectDisconnectStatus::kDisconnecting);
  connector_->StartDisconnect(
      tether_network_->guid,
      base::BindOnce(&TetherControllerImpl::OnDisconnectCompleted,
                     weak_ptr_factory_.GetWeakPtr()));
}

void TetherControllerImpl::OnDisconnectCompleted(bool success) {
  if (connect_disconnect_status_ != ConnectDisconnectStatus::kDisconnecting)
    return;

  SetConnectDisconnectStatus(ConnectDisconnectStatus::kIdle);

  if (!success)
    PA_LOG(WARNING) << "Failed to disconnect tether network";
}

void TetherControllerImpl::OnActiveNetworksChanged(
    std::vector<network_config::mojom::NetworkStatePropertiesPtr> networks) {
  // Active networks either changed externally (e.g via OS Settings or a new
  // actve network added), or as a result of a call to AttemptConnection().
  // This is needed for the case of ConnectionStateType::kConnecting in
  // ComputeStatus().
  FetchVisibleTetherNetwork();
}

void TetherControllerImpl::OnNetworkStateListChanged() {
  // Any network change whether caused externally or within this class should
  // be reflected to the state of this class (e.g user makes changes to Tether
  // network in OS Settings).
  FetchVisibleTetherNetwork();
}

void TetherControllerImpl::OnDeviceStateListChanged() {
  if (connect_disconnect_status_ !=
      ConnectDisconnectStatus::kScanningForEligiblePhone) {
    return;
  }

  cros_network_config_->GetDeviceStateList(
      base::BindOnce(&TetherControllerImpl::OnGetDeviceStateList,
                     weak_ptr_factory_.GetWeakPtr()));
}

void TetherControllerImpl::OnGetDeviceStateList(
    std::vector<DeviceStatePropertiesPtr> devices) {
  if (connect_disconnect_status_ !=
      ConnectDisconnectStatus::kScanningForEligiblePhone) {
    return;
  }

  // There should only be one Tether device in the list.
  bool is_tether_device_scanning = false;
  for (const auto& device : devices) {
    NetworkType type = device->type;
    if (type != NetworkType::kTether)
      continue;
    is_tether_device_scanning = device->scanning;
    break;
  }

  if (!is_tether_device_scanning)
    SetConnectDisconnectStatus(ConnectDisconnectStatus::kIdle);
}

void TetherControllerImpl::FetchVisibleTetherNetwork() {
  // Return the connected, connecting, or connectable Tether network.
  cros_network_config_->GetNetworkStateList(
      network_config::mojom::NetworkFilter::New(FilterType::kVisible,
                                                NetworkType::kTether,
                                                /*limit=*/0),
      base::BindOnce(&TetherControllerImpl::OnVisibleTetherNetworkFetched,
                     weak_ptr_factory_.GetWeakPtr()));
}

void TetherControllerImpl::OnVisibleTetherNetworkFetched(
    std::vector<network_config::mojom::NetworkStatePropertiesPtr> networks) {
  network_config::mojom::NetworkStatePropertiesPtr previous_tether_network =
      std::move(tether_network_);

  // The number of tether networks should only ever be at most 1.
  if (networks.size() == 1) {
    tether_network_ = std::move(networks[0]);
  } else {
    DCHECK(networks.empty());
    tether_network_ = nullptr;
  }

  // No observeable changes to the tether network specifically. This fetch
  // was initiated by a change in a non Tether network type.
  if (tether_network_.Equals(previous_tether_network))
    return;

  // If AttemptConnection() was called when Instant Tethering was disabled.
  // The feature must be enabled before scanning can occur.
  if (connect_disconnect_status_ ==
      ConnectDisconnectStatus::kTurningOnInstantTethering) {
    UpdateStatus();
    return;
  }

  // If AttemptConnection() was called when there was no available tether
  // connection.
  if (connect_disconnect_status_ ==
          ConnectDisconnectStatus::kScanningForEligiblePhone &&
      !tether_network_.is_null()) {
    StartConnect();
    return;
  }

  // If there is no attempt connection in progress, or an attempt connection
  // caused OnVisibleTetherNetworkFetched() to be fired. This case also occurs
  // in the event that Tethering settings are changed externally from this class
  // (e.g user connects via Settings).
  SetConnectDisconnectStatus(ConnectDisconnectStatus::kIdle);
}

void TetherControllerImpl::SetConnectDisconnectStatus(
    ConnectDisconnectStatus connect_disconnect_status) {
  if (connect_disconnect_status_ != connect_disconnect_status)
    weak_ptr_factory_.InvalidateWeakPtrs();
  connect_disconnect_status_ = connect_disconnect_status;
  UpdateStatus();
}

void TetherControllerImpl::UpdateStatus() {
  Status status = ComputeStatus();

  if (status_ == status)
    return;
  status_ = status;
  NotifyStatusChanged();
}

TetherController::Status TetherControllerImpl::ComputeStatus() const {
  FeatureState feature_state =
      multidevice_setup_client_->GetFeatureState(Feature::kInstantTethering);

  if (feature_state != FeatureState::kDisabledByUser &&
      feature_state != FeatureState::kEnabledByUser) {
    return Status::kIneligibleForFeature;
  }

  if (connect_disconnect_status_ ==
          ConnectDisconnectStatus::kTurningOnInstantTethering ||
      connect_disconnect_status_ ==
          ConnectDisconnectStatus::kScanningForEligiblePhone ||
      connect_disconnect_status_ ==
          ConnectDisconnectStatus::kConnectingToEligiblePhone) {
    return Status::kConnecting;
  }

  if (feature_state == FeatureState::kDisabledByUser)
    return Status::kConnectionUnavailable;

  if (tether_network_.is_null())
    return Status::kConnectionUnavailable;

  ConnectionStateType connection_state = tether_network_->connection_state;

  switch (connection_state) {
    case ConnectionStateType::kOnline:
      FALLTHROUGH;
    case ConnectionStateType::kConnected:
      FALLTHROUGH;
    case ConnectionStateType::kPortal:
      return Status::kConnected;

    case ConnectionStateType::kConnecting:
      return Status::kConnecting;

    case ConnectionStateType::kNotConnected:
      return Status::kConnectionAvailable;
  }
  return Status::kConnectionUnavailable;
}

}  // namespace phonehub
}  // namespace chromeos
