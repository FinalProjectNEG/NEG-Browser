// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/services/sharing/nearby/nearby_connections.h"

#include <stdint.h>
#include <algorithm>
#include <memory>
#include <utility>

#include "base/bind.h"
#include "base/callback.h"
#include "base/files/file_util.h"
#include "base/memory/ptr_util.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/test/bind_test_util.h"
#include "base/test/task_environment.h"
#include "chrome/services/sharing/nearby/nearby_connections_conversions.h"
#include "chrome/services/sharing/nearby/test_support/fake_adapter.h"
#include "chrome/services/sharing/nearby/test_support/mock_webrtc_dependencies.h"
#include "chromeos/services/nearby/public/mojom/nearby_decoder.mojom.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "mojo/public/cpp/bindings/self_owned_receiver.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/nearby/src/cpp/core_v2/internal/mock_service_controller.h"

namespace location {
namespace nearby {
namespace connections {

namespace {

const char kServiceId[] = "NearbySharing";
const char kFastAdvertisementServiceUuid[] =
    "0000fef3-0000-1000-8000-00805f9b34fb";
const char kRemoteEndpointId[] = "remote_endpoint_id";
const char kEndpointInfo[] = {0x0d, 0x07, 0x07, 0x07, 0x07};
const char kRemoteEndpointInfo[] = {0x0d, 0x07, 0x06, 0x08, 0x09};
const char kAuthenticationToken[] = "authentication_token";
const char kRawAuthenticationToken[] = {0x00, 0x05, 0x04, 0x03, 0x02};
const int64_t kPayloadId = 612721831;
const char kPayload[] = {0x0f, 0x0a, 0x0c, 0x0e};
const char kBluetoothMacAddress[] = {0x00, 0x00, 0xe6, 0x88, 0x64, 0x13};

mojom::AdvertisingOptionsPtr CreateAdvertisingOptions() {
  bool use_ble = false;
  auto allowed_mediums = mojom::MediumSelection::New(/*bluetooth=*/true,
                                                     /*ble=*/use_ble,
                                                     /*web_rtc=*/false,
                                                     /*wifi_lan=*/true);
  return mojom::AdvertisingOptions::New(
      mojom::Strategy::kP2pPointToPoint, std::move(allowed_mediums),
      /*auto_upgrade_bandwidth=*/true,
      /*enforce_topology_constraints=*/true,
      /*enable_bluetooth_listening=*/use_ble,
      /*fast_advertisement_service_uuid=*/
      device::BluetoothUUID(kFastAdvertisementServiceUuid));
}

mojom::ConnectionOptionsPtr CreateConnectionOptions(
    base::Optional<std::vector<uint8_t>> bluetooth_mac_address) {
  auto allowed_mediums = mojom::MediumSelection::New(/*bluetooth=*/true,
                                                     /*ble=*/false,
                                                     /*web_rtc=*/false,
                                                     /*wifi_lan=*/true);
  return mojom::ConnectionOptions::New(std::move(allowed_mediums),
                                       std::move(bluetooth_mac_address));
}

struct EndpointData {
  std::string remote_endpoint_id;
  std::vector<uint8_t> remote_endpoint_info;
};

const EndpointData CreateEndpointData(int suffix) {
  EndpointData endpoint_data;
  endpoint_data.remote_endpoint_id =
      kRemoteEndpointId + base::NumberToString(suffix);
  endpoint_data.remote_endpoint_info = std::vector<uint8_t>(
      std::begin(kRemoteEndpointInfo), std::end(kRemoteEndpointInfo));
  endpoint_data.remote_endpoint_info.push_back(suffix);
  return endpoint_data;
}

}  // namespace

class FakeEndpointDiscoveryListener : public mojom::EndpointDiscoveryListener {
 public:
  void OnEndpointFound(const std::string& endpoint_id,
                       mojom::DiscoveredEndpointInfoPtr info) override {
    endpoint_found_cb.Run(endpoint_id, std::move(info));
  }

  void OnEndpointLost(const std::string& endpoint_id) override {
    endpoint_lost_cb.Run(endpoint_id);
  }

  mojo::Receiver<mojom::EndpointDiscoveryListener> receiver{this};
  base::RepeatingCallback<void(const std::string&,
                               mojom::DiscoveredEndpointInfoPtr)>
      endpoint_found_cb = base::DoNothing();
  base::RepeatingCallback<void(const std::string&)> endpoint_lost_cb =
      base::DoNothing();
};

class FakeConnectionLifecycleListener
    : public mojom::ConnectionLifecycleListener {
 public:
  void OnConnectionInitiated(const std::string& endpoint_id,
                             mojom::ConnectionInfoPtr info) override {
    initiated_cb.Run(endpoint_id, std::move(info));
  }

  void OnConnectionAccepted(const std::string& endpoint_id) override {
    accepted_cb.Run(endpoint_id);
  }

  void OnConnectionRejected(const std::string& endpoint_id,
                            mojom::Status status) override {
    rejected_cb.Run(endpoint_id, status);
  }

  void OnDisconnected(const std::string& endpoint_id) override {
    disconnected_cb.Run(endpoint_id);
  }

  void OnBandwidthChanged(const std::string& endpoint_id,
                          mojom::Medium medium) override {
    bandwidth_changed_cb.Run(endpoint_id, medium);
  }

  mojo::Receiver<mojom::ConnectionLifecycleListener> receiver{this};
  base::RepeatingCallback<void(const std::string&, mojom::ConnectionInfoPtr)>
      initiated_cb = base::DoNothing();
  base::RepeatingCallback<void(const std::string&)> accepted_cb =
      base::DoNothing();
  base::RepeatingCallback<void(const std::string&, mojom::Status)> rejected_cb =
      base::DoNothing();
  base::RepeatingCallback<void(const std::string&)> disconnected_cb =
      base::DoNothing();
  base::RepeatingCallback<void(const std::string&, mojom::Medium)>
      bandwidth_changed_cb = base::DoNothing();
};

class FakePayloadListener : public mojom::PayloadListener {
 public:
  void OnPayloadReceived(const std::string& endpoint_id,
                         mojom::PayloadPtr payload) override {
    payload_cb.Run(endpoint_id, std::move(payload));
  }

  void OnPayloadTransferUpdate(
      const std::string& endpoint_id,
      mojom::PayloadTransferUpdatePtr update) override {
    payload_progress_cb.Run(endpoint_id, std::move(update));
  }

  mojo::Receiver<mojom::PayloadListener> receiver{this};
  base::RepeatingCallback<void(const std::string&, mojom::PayloadPtr)>
      payload_cb = base::DoNothing();
  base::RepeatingCallback<void(const std::string&,
                               mojom::PayloadTransferUpdatePtr)>
      payload_progress_cb = base::DoNothing();
};

using ::testing::_;
using ::testing::Return;
class MockInputStream : public InputStream {
 public:
  MOCK_METHOD(ExceptionOr<ByteArray>, Read, (std::int64_t), (override));
  MOCK_METHOD(Exception, Close, (), (override));
};

class NearbyConnectionsTest : public testing::Test {
 public:
  NearbyConnectionsTest() {
    auto webrtc_dependencies = mojom::WebRtcDependencies::New(
        webrtc_dependencies_.socket_manager_.BindNewPipeAndPassRemote(),
        webrtc_dependencies_.mdns_responder_.BindNewPipeAndPassRemote(),
        webrtc_dependencies_.ice_config_fetcher_.BindNewPipeAndPassRemote(),
        webrtc_dependencies_.messenger_.BindNewPipeAndPassRemote());
    auto dependencies = mojom::NearbyConnectionsDependencies::New(
        bluetooth_adapter_.adapter_.BindNewPipeAndPassRemote(),
        std::move(webrtc_dependencies));
    service_controller_ =
        std::make_unique<testing::NiceMock<MockServiceController>>();
    service_controller_ptr_ = service_controller_.get();
    nearby_connections_ = std::make_unique<NearbyConnections>(
        remote_.BindNewPipeAndPassReceiver(), std::move(dependencies),
        /*io_task_runner=*/nullptr,
        base::BindOnce(&NearbyConnectionsTest::OnDisconnect,
                       base::Unretained(this)),
        std::make_unique<Core>(
            [&]() { return service_controller_.release(); }));
  }

  void OnDisconnect() { disconnect_run_loop_.Quit(); }

  ClientProxy* StartDiscovery(
      FakeEndpointDiscoveryListener& fake_discovery_listener) {
    ClientProxy* client_proxy;
    EXPECT_CALL(*service_controller_ptr_, StartDiscovery)
        .WillOnce([&client_proxy](ClientProxy* client,
                                  const std::string& service_id,
                                  const ConnectionOptions& options,
                                  const DiscoveryListener& listener) {
          client_proxy = client;
          EXPECT_EQ(kServiceId, service_id);
          EXPECT_EQ(Strategy::kP2pPointToPoint, options.strategy);
          EXPECT_TRUE(options.allowed.bluetooth);
          EXPECT_FALSE(options.allowed.ble);
          EXPECT_FALSE(options.allowed.web_rtc);
          EXPECT_TRUE(options.allowed.wifi_lan);
          EXPECT_EQ(kFastAdvertisementServiceUuid,
                    options.fast_advertisement_service_uuid);
          client->StartedDiscovery(service_id, options.strategy, listener,
                                   /*mediums=*/{});
          return Status{Status::kAlreadyDiscovering};
        });
    base::RunLoop start_discovery_run_loop;
    nearby_connections_->StartDiscovery(
        kServiceId,
        mojom::DiscoveryOptions::New(
            mojom::Strategy::kP2pPointToPoint,
            mojom::MediumSelection::New(/*bluetooth=*/true,
                                        /*ble=*/false,
                                        /*web_rtc=*/false,
                                        /*wifi_lan=*/true),
            device::BluetoothUUID(kFastAdvertisementServiceUuid)),
        fake_discovery_listener.receiver.BindNewPipeAndPassRemote(),
        base::BindLambdaForTesting([&](mojom::Status status) {
          EXPECT_EQ(mojom::Status::kAlreadyDiscovering, status);
          start_discovery_run_loop.Quit();
        }));
    start_discovery_run_loop.Run();

    return client_proxy;
  }

  ClientProxy* StartAdvertising(
      FakeConnectionLifecycleListener& fake_connection_life_cycle_listener,
      const EndpointData& endpoint_data) {
    ClientProxy* client_proxy;
    std::vector<uint8_t> endpoint_info(std::begin(kEndpointInfo),
                                       std::end(kEndpointInfo));
    EXPECT_CALL(*service_controller_ptr_, StartAdvertising)
        .WillOnce([&](ClientProxy* client, const std::string& service_id,
                      const ConnectionOptions& options,
                      const ConnectionRequestInfo& info) {
          client_proxy = client;
          EXPECT_EQ(kServiceId, service_id);
          EXPECT_EQ(Strategy::kP2pPointToPoint, options.strategy);
          EXPECT_TRUE(options.allowed.bluetooth);
          EXPECT_FALSE(options.allowed.web_rtc);
          EXPECT_TRUE(options.allowed.wifi_lan);
          EXPECT_TRUE(options.auto_upgrade_bandwidth);
          EXPECT_TRUE(options.enforce_topology_constraints);
          EXPECT_EQ(endpoint_info, ByteArrayToMojom(info.endpoint_info));

          client_proxy->StartedAdvertising(service_id, options.strategy,
                                           info.listener,
                                           /*mediums=*/{});
          client_proxy->OnConnectionInitiated(
              endpoint_data.remote_endpoint_id,
              {.remote_endpoint_info =
                   ByteArrayFromMojom(endpoint_data.remote_endpoint_info),
               .authentication_token = kAuthenticationToken,
               .raw_authentication_token = ByteArray(
                   kRawAuthenticationToken, sizeof(kRawAuthenticationToken)),
               .is_incoming_connection = false},
              options, info.listener);
          return Status{Status::kSuccess};
        });

    base::RunLoop start_advertising_run_loop;
    nearby_connections_->StartAdvertising(
        endpoint_info, kServiceId, CreateAdvertisingOptions(),
        fake_connection_life_cycle_listener.receiver.BindNewPipeAndPassRemote(),
        base::BindLambdaForTesting([&](mojom::Status status) {
          EXPECT_EQ(mojom::Status::kSuccess, status);
          start_advertising_run_loop.Quit();
        }));
    start_advertising_run_loop.Run();

    return client_proxy;
  }

  ClientProxy* RequestConnection(
      FakeConnectionLifecycleListener& fake_connection_life_cycle_listener,
      const EndpointData& endpoint_data,
      base::Optional<std::vector<uint8_t>> bluetooth_mac_address =
          std::vector<uint8_t>(std::begin(kBluetoothMacAddress),
                               std::end(kBluetoothMacAddress))) {
    ClientProxy* client_proxy;
    std::vector<uint8_t> endpoint_info(std::begin(kEndpointInfo),
                                       std::end(kEndpointInfo));
    EXPECT_CALL(*service_controller_ptr_, RequestConnection)
        .WillOnce([&](ClientProxy* client, const std::string& endpoint_id,
                      const ConnectionRequestInfo& info,
                      const ConnectionOptions& options) {
          client_proxy = client;
          EXPECT_EQ(endpoint_data.remote_endpoint_id, endpoint_id);
          EXPECT_EQ(endpoint_info, ByteArrayToMojom(info.endpoint_info));
          EXPECT_TRUE(options.allowed.bluetooth);
          EXPECT_FALSE(options.allowed.web_rtc);
          EXPECT_TRUE(options.allowed.wifi_lan);
          if (bluetooth_mac_address) {
            EXPECT_EQ(bluetooth_mac_address,
                      ByteArrayToMojom(options.remote_bluetooth_mac_address));
          } else {
            EXPECT_TRUE(options.remote_bluetooth_mac_address.Empty());
          }
          client_proxy->OnConnectionInitiated(
              endpoint_id,
              {.remote_endpoint_info =
                   ByteArrayFromMojom(endpoint_data.remote_endpoint_info),
               .authentication_token = kAuthenticationToken,
               .raw_authentication_token = ByteArray(
                   kRawAuthenticationToken, sizeof(kRawAuthenticationToken)),
               .is_incoming_connection = false},
              options, info.listener);
          return Status{Status::kSuccess};
        });

    base::RunLoop request_connection_run_loop;
    nearby_connections_->RequestConnection(
        endpoint_info, endpoint_data.remote_endpoint_id,
        CreateConnectionOptions(bluetooth_mac_address),
        fake_connection_life_cycle_listener.receiver.BindNewPipeAndPassRemote(),
        base::BindLambdaForTesting([&](mojom::Status status) {
          EXPECT_EQ(mojom::Status::kSuccess, status);
          request_connection_run_loop.Quit();
        }));
    request_connection_run_loop.Run();

    return client_proxy;
  }

  ClientProxy* AcceptConnection(FakePayloadListener& fake_payload_listener,
                                const std::string& remote_endpoint_id) {
    ClientProxy* client_proxy;
    EXPECT_CALL(*service_controller_ptr_, AcceptConnection)
        .WillOnce([&client_proxy, &remote_endpoint_id](
                      ClientProxy* client, const std::string& endpoint_id,
                      const PayloadListener& listener) {
          client_proxy = client;
          EXPECT_EQ(remote_endpoint_id, endpoint_id);
          client_proxy->LocalEndpointAcceptedConnection(endpoint_id, listener);
          client_proxy->OnConnectionAccepted(endpoint_id);
          return Status{Status::kSuccess};
        });

    base::RunLoop accept_connection_run_loop;
    nearby_connections_->AcceptConnection(
        remote_endpoint_id,
        fake_payload_listener.receiver.BindNewPipeAndPassRemote(),
        base::BindLambdaForTesting([&](mojom::Status status) {
          EXPECT_EQ(mojom::Status::kSuccess, status);
          accept_connection_run_loop.Quit();
        }));
    accept_connection_run_loop.Run();

    return client_proxy;
  }

 protected:
  base::test::TaskEnvironment task_environment_;
  mojo::Remote<mojom::NearbyConnections> remote_;
  bluetooth::FakeAdapter bluetooth_adapter_;
  sharing::MockWebRtcDependencies webrtc_dependencies_;
  std::unique_ptr<NearbyConnections> nearby_connections_;
  testing::NiceMock<MockServiceController>* service_controller_ptr_;
  base::RunLoop disconnect_run_loop_;

 private:
  std::unique_ptr<testing::NiceMock<MockServiceController>> service_controller_;
};

TEST_F(NearbyConnectionsTest, RemoteDisconnect) {
  remote_.reset();
  disconnect_run_loop_.Run();
}

TEST_F(NearbyConnectionsTest, BluetoothDisconnect) {
  bluetooth_adapter_.adapter_.reset();
  disconnect_run_loop_.Run();
}

TEST_F(NearbyConnectionsTest, P2PSocketManagerDisconnect) {
  webrtc_dependencies_.socket_manager_.reset();
  disconnect_run_loop_.Run();
}

TEST_F(NearbyConnectionsTest, MdnsResponderDisconnect) {
  webrtc_dependencies_.mdns_responder_.reset();
  disconnect_run_loop_.Run();
}

TEST_F(NearbyConnectionsTest, IceConfigFetcherDisconnect) {
  webrtc_dependencies_.ice_config_fetcher_.reset();
  disconnect_run_loop_.Run();
}

TEST_F(NearbyConnectionsTest, WebRtcSignalingMessengerDisconnect) {
  webrtc_dependencies_.messenger_.reset();
  disconnect_run_loop_.Run();
}

TEST_F(NearbyConnectionsTest, StartDiscovery) {
  FakeEndpointDiscoveryListener fake_discovery_listener;
  ClientProxy* client_proxy = StartDiscovery(fake_discovery_listener);

  base::RunLoop endpoint_found_run_loop;
  EndpointData endpoint_data = CreateEndpointData(1);
  fake_discovery_listener.endpoint_found_cb =
      base::BindLambdaForTesting([&](const std::string& endpoint_id,
                                     mojom::DiscoveredEndpointInfoPtr info) {
        EXPECT_EQ(endpoint_data.remote_endpoint_id, endpoint_id);
        EXPECT_EQ(endpoint_data.remote_endpoint_info, info->endpoint_info);
        EXPECT_EQ(kServiceId, info->service_id);
        endpoint_found_run_loop.Quit();
      });

  client_proxy->OnEndpointFound(
      kServiceId, endpoint_data.remote_endpoint_id,
      ByteArrayFromMojom(endpoint_data.remote_endpoint_info),
      /*mediums=*/{});
  endpoint_found_run_loop.Run();

  base::RunLoop endpoint_lost_run_loop;
  fake_discovery_listener.endpoint_lost_cb =
      base::BindLambdaForTesting([&](const std::string& endpoint_id) {
        EXPECT_EQ(endpoint_data.remote_endpoint_id, endpoint_id);
        endpoint_lost_run_loop.Quit();
      });
  client_proxy->OnEndpointLost(kServiceId, endpoint_data.remote_endpoint_id);
  endpoint_lost_run_loop.Run();
}

TEST_F(NearbyConnectionsTest, StopDiscovery) {
  FakeEndpointDiscoveryListener fake_discovery_listener;
  StartDiscovery(fake_discovery_listener);

  EXPECT_CALL(*service_controller_ptr_, StopDiscovery(testing::_)).Times(1);

  base::RunLoop stop_discovery_run_loop;
  nearby_connections_->StopDiscovery(
      base::BindLambdaForTesting([&](mojom::Status status) {
        EXPECT_EQ(mojom::Status::kSuccess, status);
        stop_discovery_run_loop.Quit();
      }));
  stop_discovery_run_loop.Run();

  // StopDiscovery is also called when Core is destroyed.
  EXPECT_CALL(*service_controller_ptr_, StopDiscovery(testing::_)).Times(1);
}

TEST_F(NearbyConnectionsTest, RequestConnectionInitiated) {
  FakeEndpointDiscoveryListener fake_discovery_listener;
  EndpointData endpoint_data = CreateEndpointData(1);
  ClientProxy* client_proxy = StartDiscovery(fake_discovery_listener);
  client_proxy->OnEndpointFound(
      kServiceId, endpoint_data.remote_endpoint_id,
      ByteArrayFromMojom(endpoint_data.remote_endpoint_info),
      /*mediums=*/{});

  base::RunLoop initiated_run_loop;
  FakeConnectionLifecycleListener fake_connection_life_cycle_listener;
  fake_connection_life_cycle_listener.initiated_cb = base::BindLambdaForTesting(
      [&](const std::string& endpoint_id, mojom::ConnectionInfoPtr info) {
        EXPECT_EQ(endpoint_data.remote_endpoint_id, endpoint_id);
        EXPECT_EQ(kAuthenticationToken, info->authentication_token);
        EXPECT_EQ(std::vector<uint8_t>(std::begin(kRawAuthenticationToken),
                                       std::end(kRawAuthenticationToken)),
                  info->raw_authentication_token);
        EXPECT_EQ(endpoint_data.remote_endpoint_info, info->endpoint_info);
        EXPECT_FALSE(info->is_incoming_connection);
        initiated_run_loop.Quit();
      });

  RequestConnection(fake_connection_life_cycle_listener, endpoint_data);
  initiated_run_loop.Run();
}

TEST_F(NearbyConnectionsTest,
       RequestConnectionInitiatedWithoutBluetotohMacAddress) {
  FakeEndpointDiscoveryListener fake_discovery_listener;
  EndpointData endpoint_data = CreateEndpointData(1);
  ClientProxy* client_proxy = StartDiscovery(fake_discovery_listener);
  client_proxy->OnEndpointFound(
      kServiceId, endpoint_data.remote_endpoint_id,
      ByteArrayFromMojom(endpoint_data.remote_endpoint_info),
      /*mediums=*/{});

  FakeConnectionLifecycleListener fake_connection_life_cycle_listener;

  RequestConnection(fake_connection_life_cycle_listener, endpoint_data,
                    /*bluetooth_mac_address=*/base::nullopt);
}

TEST_F(NearbyConnectionsTest, RequestConnectionAccept) {
  FakeEndpointDiscoveryListener fake_discovery_listener;
  EndpointData endpoint_data = CreateEndpointData(1);
  ClientProxy* client_proxy = StartDiscovery(fake_discovery_listener);
  client_proxy->OnEndpointFound(
      kServiceId, endpoint_data.remote_endpoint_id,
      ByteArrayFromMojom(endpoint_data.remote_endpoint_info),
      /*mediums=*/{});

  FakeConnectionLifecycleListener fake_connection_life_cycle_listener;
  RequestConnection(fake_connection_life_cycle_listener, endpoint_data);

  base::RunLoop accepted_run_loop;
  fake_connection_life_cycle_listener.accepted_cb =
      base::BindLambdaForTesting([&](const std::string& endpoint_id) {
        EXPECT_EQ(endpoint_data.remote_endpoint_id, endpoint_id);
        accepted_run_loop.Quit();
      });

  FakePayloadListener fake_payload_listener;
  AcceptConnection(fake_payload_listener, endpoint_data.remote_endpoint_id);
  accepted_run_loop.Run();
}

TEST_F(NearbyConnectionsTest, RequestConnectionOnRejected) {
  FakeEndpointDiscoveryListener fake_discovery_listener;
  EndpointData endpoint_data = CreateEndpointData(1);
  ClientProxy* client_proxy = StartDiscovery(fake_discovery_listener);
  client_proxy->OnEndpointFound(
      kServiceId, endpoint_data.remote_endpoint_id,
      ByteArrayFromMojom(endpoint_data.remote_endpoint_info),
      /*mediums=*/{});

  FakeConnectionLifecycleListener fake_connection_life_cycle_listener;
  client_proxy =
      RequestConnection(fake_connection_life_cycle_listener, endpoint_data);

  base::RunLoop rejected_run_loop;
  fake_connection_life_cycle_listener.rejected_cb = base::BindLambdaForTesting(
      [&](const std::string& endpoint_id, mojom::Status status) {
        EXPECT_EQ(endpoint_data.remote_endpoint_id, endpoint_id);
        EXPECT_EQ(mojom::Status::kConnectionRejected, status);
        rejected_run_loop.Quit();
      });

  client_proxy->OnConnectionRejected(endpoint_data.remote_endpoint_id,
                                     {Status::kConnectionRejected});
  rejected_run_loop.Run();
}

TEST_F(NearbyConnectionsTest, RequestConnectionOnBandwidthUpgrade) {
  FakeEndpointDiscoveryListener fake_discovery_listener;
  EndpointData endpoint_data = CreateEndpointData(1);
  ClientProxy* client_proxy = StartDiscovery(fake_discovery_listener);
  client_proxy->OnEndpointFound(
      kServiceId, endpoint_data.remote_endpoint_id,
      ByteArrayFromMojom(endpoint_data.remote_endpoint_info),
      /*mediums=*/{});

  FakeConnectionLifecycleListener fake_connection_life_cycle_listener;
  RequestConnection(fake_connection_life_cycle_listener, endpoint_data);

  FakePayloadListener fake_payload_listener;
  client_proxy =
      AcceptConnection(fake_payload_listener, endpoint_data.remote_endpoint_id);

  // The life cycle listener should be triggered by a bandwidth upgrade.
  base::RunLoop upgraded_run_loop;
  fake_connection_life_cycle_listener.bandwidth_changed_cb =
      base::BindLambdaForTesting(
          [&](const std::string& endpoint_id, mojom::Medium medium) {
            EXPECT_EQ(endpoint_data.remote_endpoint_id, endpoint_id);
            EXPECT_EQ(mojom::Medium::kWebRtc, medium);
            upgraded_run_loop.Quit();
          });

  // Requesting a bandwidth upgrade should succeed.
  EXPECT_CALL(*service_controller_ptr_, InitiateBandwidthUpgrade)
      .WillOnce([&](ClientProxy* client, const std::string& endpoint_id) {
        client_proxy = client;
        EXPECT_EQ(endpoint_data.remote_endpoint_id, endpoint_id);
        client_proxy->OnBandwidthChanged(endpoint_id, Medium::WEB_RTC);
        return Status{Status::kSuccess};
      });
  base::RunLoop bandwidth_upgrade_run_loop;
  nearby_connections_->InitiateBandwidthUpgrade(
      endpoint_data.remote_endpoint_id,
      base::BindLambdaForTesting([&](mojom::Status status) {
        EXPECT_EQ(mojom::Status::kSuccess, status);
        bandwidth_upgrade_run_loop.Quit();
      }));
  bandwidth_upgrade_run_loop.Run();

  upgraded_run_loop.Run();
}

TEST_F(NearbyConnectionsTest, RequestConnectionOnDisconnected) {
  FakeEndpointDiscoveryListener fake_discovery_listener;
  EndpointData endpoint_data = CreateEndpointData(1);
  ClientProxy* client_proxy = StartDiscovery(fake_discovery_listener);
  client_proxy->OnEndpointFound(
      kServiceId, endpoint_data.remote_endpoint_id,
      ByteArrayFromMojom(endpoint_data.remote_endpoint_info),
      /*mediums=*/{});

  FakeConnectionLifecycleListener fake_connection_life_cycle_listener;
  RequestConnection(fake_connection_life_cycle_listener, endpoint_data);

  FakePayloadListener fake_payload_listener;
  client_proxy =
      AcceptConnection(fake_payload_listener, endpoint_data.remote_endpoint_id);

  base::RunLoop disconnected_run_loop;
  fake_connection_life_cycle_listener.disconnected_cb =
      base::BindLambdaForTesting([&](const std::string& endpoint_id) {
        EXPECT_EQ(endpoint_data.remote_endpoint_id, endpoint_id);
        disconnected_run_loop.Quit();
      });

  client_proxy->OnDisconnected(endpoint_data.remote_endpoint_id,
                               /*notify=*/true);
  disconnected_run_loop.Run();
}

TEST_F(NearbyConnectionsTest, RequestConnectionDisconnect) {
  FakeEndpointDiscoveryListener fake_discovery_listener;
  EndpointData endpoint_data = CreateEndpointData(1);
  ClientProxy* client_proxy = StartDiscovery(fake_discovery_listener);
  client_proxy->OnEndpointFound(
      kServiceId, endpoint_data.remote_endpoint_id,
      ByteArrayFromMojom(endpoint_data.remote_endpoint_info),
      /*mediums=*/{});

  FakeConnectionLifecycleListener fake_connection_life_cycle_listener;
  RequestConnection(fake_connection_life_cycle_listener, endpoint_data);

  FakePayloadListener fake_payload_listener;
  AcceptConnection(fake_payload_listener, endpoint_data.remote_endpoint_id);

  EXPECT_CALL(*service_controller_ptr_, DisconnectFromEndpoint)
      .WillOnce([&](ClientProxy* client, const std::string& endpoint_id) {
        EXPECT_EQ(endpoint_data.remote_endpoint_id, endpoint_id);
        client->OnDisconnected(endpoint_id, /*notify=*/true);
        return Status{Status::kSuccess};
      });

  base::RunLoop disconnected_run_loop;
  fake_connection_life_cycle_listener.disconnected_cb =
      base::BindLambdaForTesting([&](const std::string& endpoint_id) {
        EXPECT_EQ(endpoint_data.remote_endpoint_id, endpoint_id);
        disconnected_run_loop.Quit();
      });

  base::RunLoop disconnect_from_endpoint_run_loop;
  nearby_connections_->DisconnectFromEndpoint(
      endpoint_data.remote_endpoint_id,
      base::BindLambdaForTesting([&](mojom::Status status) {
        EXPECT_EQ(mojom::Status::kSuccess, status);
        disconnect_from_endpoint_run_loop.Quit();
      }));
  disconnect_from_endpoint_run_loop.Run();
  disconnected_run_loop.Run();
}

TEST_F(NearbyConnectionsTest, OnPayloadTransferUpdate) {
  FakeEndpointDiscoveryListener fake_discovery_listener;
  EndpointData endpoint_data = CreateEndpointData(1);
  ClientProxy* client_proxy = StartDiscovery(fake_discovery_listener);
  client_proxy->OnEndpointFound(
      kServiceId, endpoint_data.remote_endpoint_id,
      ByteArrayFromMojom(endpoint_data.remote_endpoint_info),
      /*mediums=*/{});

  FakeConnectionLifecycleListener fake_connection_life_cycle_listener;
  RequestConnection(fake_connection_life_cycle_listener, endpoint_data);

  FakePayloadListener fake_payload_listener;
  client_proxy =
      AcceptConnection(fake_payload_listener, endpoint_data.remote_endpoint_id);

  base::RunLoop payload_progress_run_loop;
  fake_payload_listener.payload_progress_cb =
      base::BindLambdaForTesting([&](const std::string& endpoint_id,
                                     mojom::PayloadTransferUpdatePtr info) {
        EXPECT_EQ(endpoint_data.remote_endpoint_id, endpoint_id);
        payload_progress_run_loop.Quit();
      });

  client_proxy->OnPayloadProgress(endpoint_data.remote_endpoint_id, {});
  payload_progress_run_loop.Run();
}

TEST_F(NearbyConnectionsTest, SendBytesPayload) {
  const std::vector<uint8_t> expected_payload(std::begin(kPayload),
                                              std::end(kPayload));

  FakeEndpointDiscoveryListener fake_discovery_listener;
  EndpointData endpoint_data = CreateEndpointData(1);
  ClientProxy* client_proxy = StartDiscovery(fake_discovery_listener);
  client_proxy->OnEndpointFound(
      kServiceId, endpoint_data.remote_endpoint_id,
      ByteArrayFromMojom(endpoint_data.remote_endpoint_info),
      /*mediums=*/{});

  FakeConnectionLifecycleListener fake_connection_life_cycle_listener;
  RequestConnection(fake_connection_life_cycle_listener, endpoint_data);

  FakePayloadListener fake_payload_listener;
  AcceptConnection(fake_payload_listener, endpoint_data.remote_endpoint_id);

  EXPECT_CALL(*service_controller_ptr_, SendPayload)
      .WillOnce([&](ClientProxy* client,
                    const std::vector<std::string>& endpoint_ids,
                    Payload payload) {
        ASSERT_EQ(1u, endpoint_ids.size());
        EXPECT_EQ(endpoint_data.remote_endpoint_id, endpoint_ids.front());
        EXPECT_EQ(Payload::Type::kBytes, payload.GetType());
        std::string payload_bytes(payload.AsBytes());
        EXPECT_EQ(expected_payload, ByteArrayToMojom(payload.AsBytes()));
      });

  base::RunLoop send_payload_run_loop;
  nearby_connections_->SendPayload(
      {endpoint_data.remote_endpoint_id},
      mojom::Payload::New(kPayloadId,
                          mojom::PayloadContent::NewBytes(
                              mojom::BytesPayload::New(expected_payload))),
      base::BindLambdaForTesting([&](mojom::Status status) {
        EXPECT_EQ(mojom::Status::kSuccess, status);
        send_payload_run_loop.Quit();
      }));
  send_payload_run_loop.Run();
}

TEST_F(NearbyConnectionsTest, SendBytesPayloadCancelled) {
  const std::vector<uint8_t> expected_payload(std::begin(kPayload),
                                              std::end(kPayload));

  FakeEndpointDiscoveryListener fake_discovery_listener;
  ClientProxy* client_proxy = StartDiscovery(fake_discovery_listener);
  EndpointData endpoint_data = CreateEndpointData(1);
  client_proxy->OnEndpointFound(
      kServiceId, endpoint_data.remote_endpoint_id,
      ByteArrayFromMojom(endpoint_data.remote_endpoint_info),
      /*mediums=*/{});

  FakeConnectionLifecycleListener fake_connection_life_cycle_listener;
  client_proxy =
      RequestConnection(fake_connection_life_cycle_listener, endpoint_data);

  FakePayloadListener fake_payload_listener;
  client_proxy =
      AcceptConnection(fake_payload_listener, endpoint_data.remote_endpoint_id);

  EXPECT_CALL(*service_controller_ptr_, SendPayload)
      .WillOnce([&](ClientProxy* client,
                    const std::vector<std::string>& endpoint_ids,
                    Payload payload) {
        ASSERT_EQ(1u, endpoint_ids.size());
        EXPECT_EQ(endpoint_data.remote_endpoint_id, endpoint_ids.front());
        EXPECT_EQ(Payload::Type::kBytes, payload.GetType());
        std::string payload_bytes(payload.AsBytes());
        EXPECT_EQ(expected_payload, ByteArrayToMojom(payload.AsBytes()));
      });

  base::RunLoop send_payload_run_loop;
  nearby_connections_->SendPayload(
      {endpoint_data.remote_endpoint_id},
      mojom::Payload::New(kPayloadId,
                          mojom::PayloadContent::NewBytes(
                              mojom::BytesPayload::New(expected_payload))),
      base::BindLambdaForTesting([&](mojom::Status status) {
        EXPECT_EQ(mojom::Status::kSuccess, status);
        send_payload_run_loop.Quit();
      }));
  send_payload_run_loop.Run();

  EXPECT_CALL(*service_controller_ptr_,
              CancelPayload(testing::_, testing::Eq(kPayloadId)))
      .WillOnce(testing::Return(Status{Status::kSuccess}));

  base::RunLoop cancel_payload_run_loop;
  nearby_connections_->CancelPayload(
      kPayloadId, base::BindLambdaForTesting([&](mojom::Status status) {
        EXPECT_EQ(mojom::Status::kSuccess, status);
        cancel_payload_run_loop.Quit();
      }));
  cancel_payload_run_loop.Run();
}

TEST_F(NearbyConnectionsTest, SendFilePayload) {
  const std::vector<uint8_t> expected_payload(std::begin(kPayload),
                                              std::end(kPayload));

  FakeEndpointDiscoveryListener fake_discovery_listener;
  EndpointData endpoint_data = CreateEndpointData(1);
  ClientProxy* client_proxy = StartDiscovery(fake_discovery_listener);
  client_proxy->OnEndpointFound(
      kServiceId, endpoint_data.remote_endpoint_id,
      ByteArrayFromMojom(endpoint_data.remote_endpoint_info),
      /*mediums=*/{});

  FakeConnectionLifecycleListener fake_connection_life_cycle_listener;
  RequestConnection(fake_connection_life_cycle_listener, endpoint_data);

  FakePayloadListener fake_payload_listener;
  AcceptConnection(fake_payload_listener, endpoint_data.remote_endpoint_id);

  EXPECT_CALL(*service_controller_ptr_, SendPayload)
      .WillOnce([&](ClientProxy* client,
                    const std::vector<std::string>& endpoint_ids,
                    Payload payload) {
        ASSERT_EQ(1u, endpoint_ids.size());
        EXPECT_EQ(endpoint_data.remote_endpoint_id, endpoint_ids.front());
        EXPECT_EQ(Payload::Type::kFile, payload.GetType());
        InputFile* file = payload.AsFile();
        ASSERT_TRUE(file);
        ExceptionOr<ByteArray> bytes = file->Read(file->GetTotalSize());
        ASSERT_TRUE(bytes.ok());
        EXPECT_EQ(expected_payload, ByteArrayToMojom(bytes.result()));
      });

  base::FilePath path;
  EXPECT_TRUE(base::CreateTemporaryFile(&path));
  base::File output_file(path, base::File::Flags::FLAG_CREATE_ALWAYS |
                                   base::File::Flags::FLAG_WRITE);
  ASSERT_TRUE(output_file.IsValid());
  EXPECT_TRUE(output_file.WriteAndCheck(
      /*offset=*/0, base::make_span(expected_payload)));
  EXPECT_TRUE(output_file.Flush());
  output_file.Close();

  base::File input_file(
      path, base::File::Flags::FLAG_OPEN | base::File::Flags::FLAG_READ);
  EXPECT_TRUE(input_file.IsValid());

  base::RunLoop send_payload_run_loop;
  nearby_connections_->SendPayload(
      {endpoint_data.remote_endpoint_id},
      mojom::Payload::New(kPayloadId,
                          mojom::PayloadContent::NewFile(
                              mojom::FilePayload::New(std::move(input_file)))),
      base::BindLambdaForTesting([&](mojom::Status status) {
        EXPECT_EQ(mojom::Status::kSuccess, status);
        send_payload_run_loop.Quit();
      }));
  send_payload_run_loop.Run();
}

TEST_F(NearbyConnectionsTest, StartAdvertisingRejected) {
  FakeConnectionLifecycleListener fake_connection_life_cycle_listener;
  EndpointData endpoint_data = CreateEndpointData(1);

  base::RunLoop initiated_run_loop;
  fake_connection_life_cycle_listener.initiated_cb = base::BindLambdaForTesting(
      [&](const std::string& endpoint_id, mojom::ConnectionInfoPtr info) {
        EXPECT_EQ(endpoint_data.remote_endpoint_id, endpoint_id);
        EXPECT_EQ(kAuthenticationToken, info->authentication_token);
        EXPECT_EQ(std::vector<uint8_t>(std::begin(kRawAuthenticationToken),
                                       std::end(kRawAuthenticationToken)),
                  info->raw_authentication_token);
        EXPECT_EQ(endpoint_data.remote_endpoint_info, info->endpoint_info);
        EXPECT_FALSE(info->is_incoming_connection);
        initiated_run_loop.Quit();
      });

  ClientProxy* client_proxy =
      StartAdvertising(fake_connection_life_cycle_listener, endpoint_data);
  initiated_run_loop.Run();

  base::RunLoop rejected_run_loop;
  fake_connection_life_cycle_listener.rejected_cb = base::BindLambdaForTesting(
      [&](const std::string& endpoint_id, mojom::Status status) {
        EXPECT_EQ(endpoint_data.remote_endpoint_id, endpoint_id);
        EXPECT_EQ(mojom::Status::kConnectionRejected, status);
        rejected_run_loop.Quit();
      });
  client_proxy->OnConnectionRejected(endpoint_data.remote_endpoint_id,
                                     {Status::kConnectionRejected});
  rejected_run_loop.Run();
}

TEST_F(NearbyConnectionsTest, StartAdvertisingAccepted) {
  FakeConnectionLifecycleListener fake_connection_life_cycle_listener;
  EndpointData endpoint_data = CreateEndpointData(1);

  base::RunLoop initiated_run_loop;
  fake_connection_life_cycle_listener.initiated_cb = base::BindLambdaForTesting(
      [&](const std::string& endpoint_id, mojom::ConnectionInfoPtr info) {
        EXPECT_EQ(endpoint_data.remote_endpoint_id, endpoint_id);
        EXPECT_EQ(kAuthenticationToken, info->authentication_token);
        EXPECT_EQ(std::vector<uint8_t>(std::begin(kRawAuthenticationToken),
                                       std::end(kRawAuthenticationToken)),
                  info->raw_authentication_token);
        EXPECT_EQ(endpoint_data.remote_endpoint_info, info->endpoint_info);
        EXPECT_FALSE(info->is_incoming_connection);
        initiated_run_loop.Quit();
      });

  ClientProxy* client_proxy =
      StartAdvertising(fake_connection_life_cycle_listener, endpoint_data);
  initiated_run_loop.Run();

  base::RunLoop accepted_run_loop;
  fake_connection_life_cycle_listener.accepted_cb =
      base::BindLambdaForTesting([&](const std::string& endpoint_id) {
        EXPECT_EQ(endpoint_data.remote_endpoint_id, endpoint_id);
        accepted_run_loop.Quit();
      });

  FakePayloadListener fake_payload_listener;
  client_proxy =
      AcceptConnection(fake_payload_listener, endpoint_data.remote_endpoint_id);
  accepted_run_loop.Run();
}

TEST_F(NearbyConnectionsTest, StopAdvertising) {
  FakeConnectionLifecycleListener fake_connection_life_cycle_listener;
  EndpointData endpoint_data = CreateEndpointData(1);
  StartAdvertising(fake_connection_life_cycle_listener, endpoint_data);

  EXPECT_CALL(*service_controller_ptr_, StopAdvertising)
      .WillOnce([](ClientProxy* client) { client->StoppedAdvertising(); });

  base::RunLoop stop_advertising_run_loop;
  nearby_connections_->StopAdvertising(
      base::BindLambdaForTesting([&](mojom::Status status) {
        EXPECT_EQ(mojom::Status::kSuccess, status);
        stop_advertising_run_loop.Quit();
      }));
  stop_advertising_run_loop.Run();

  // Expect one more call during shutdown.
  EXPECT_CALL(*service_controller_ptr_, StopAdvertising);
}

TEST_F(NearbyConnectionsTest, DisconnectAllEndpoints) {
  FakeEndpointDiscoveryListener fake_discovery_listener;
  EndpointData endpoint_data = CreateEndpointData(1);
  ClientProxy* client_proxy = StartDiscovery(fake_discovery_listener);
  client_proxy->OnEndpointFound(
      kServiceId, endpoint_data.remote_endpoint_id,
      ByteArrayFromMojom(endpoint_data.remote_endpoint_info),
      /*mediums=*/{});

  // Set up a connection to one endpoint.
  FakeConnectionLifecycleListener fake_connection_life_cycle_listener;
  ConnectionListener connections_listener;
  RequestConnection(fake_connection_life_cycle_listener, endpoint_data);

  FakePayloadListener fake_payload_listener;
  AcceptConnection(fake_payload_listener, endpoint_data.remote_endpoint_id);

  // Set up a pending connection to a different endpoint.
  EndpointData endpoint_data2 = CreateEndpointData(2);
  client_proxy->OnEndpointFound(
      kServiceId, endpoint_data2.remote_endpoint_id,
      ByteArrayFromMojom(endpoint_data2.remote_endpoint_info),
      /*mediums=*/{});

  FakeConnectionLifecycleListener fake_connection_life_cycle_listener2;
  ConnectionListener connections_listener2;
  RequestConnection(fake_connection_life_cycle_listener2, endpoint_data2);

  // Stop all endpoints should invoke disconnect for both endpoints.
  EXPECT_CALL(*service_controller_ptr_,
              DisconnectFromEndpoint(_, endpoint_data.remote_endpoint_id))
      .WillOnce([](ClientProxy* client, const std::string& endpoint_id) {
        return Status{Status::kSuccess};
      });
  EXPECT_CALL(*service_controller_ptr_,
              DisconnectFromEndpoint(_, endpoint_data2.remote_endpoint_id))
      .WillOnce([](ClientProxy* client, const std::string& endpoint_id) {
        return Status{Status::kSuccess};
      });
  // Stop all endpoints should stop both advertising and discovery.
  EXPECT_CALL(*service_controller_ptr_, StopAdvertising);
  EXPECT_CALL(*service_controller_ptr_, StopDiscovery);

  base::RunLoop stop_endpoints_run_loop;
  nearby_connections_->StopAllEndpoints(
      base::BindLambdaForTesting([&](mojom::Status status) {
        EXPECT_EQ(mojom::Status::kSuccess, status);
        stop_endpoints_run_loop.Quit();
      }));
  stop_endpoints_run_loop.Run();
}

TEST_F(NearbyConnectionsTest, InitiateBandwidthUpgrade) {
  // TODO(nmusgrave) test upgrade
  // upgrade should fail if not advertising or discovering
  // upgrade should fail if not a connection in place
}

TEST_F(NearbyConnectionsTest, InitiateBandwidthUpgradeFails) {
  EndpointData endpoint_data = CreateEndpointData(1);
  base::RunLoop bandwidth_upgrade_run_loop;
  nearby_connections_->InitiateBandwidthUpgrade(
      endpoint_data.remote_endpoint_id,
      base::BindLambdaForTesting([&](mojom::Status status) {
        EXPECT_EQ(mojom::Status::kOutOfOrderApiCall, status);
        bandwidth_upgrade_run_loop.Quit();
      }));
  bandwidth_upgrade_run_loop.Run();
}

TEST_F(NearbyConnectionsTest, InitiateBandwidthUpgradeAfterDiscoveringFails) {
  FakeEndpointDiscoveryListener fake_discovery_listener;
  EndpointData endpoint_data = CreateEndpointData(1);
  ClientProxy* client_proxy = StartDiscovery(fake_discovery_listener);
  client_proxy->OnEndpointFound(
      kServiceId, endpoint_data.remote_endpoint_id,
      ByteArrayFromMojom(endpoint_data.remote_endpoint_info),
      /*mediums=*/{});

  // Requesting a bandwidth upgrade should fail.
  base::RunLoop bandwidth_upgrade_run_loop;
  nearby_connections_->InitiateBandwidthUpgrade(
      endpoint_data.remote_endpoint_id,
      base::BindLambdaForTesting([&](mojom::Status status) {
        EXPECT_EQ(mojom::Status::kOutOfOrderApiCall, status);
        bandwidth_upgrade_run_loop.Quit();
      }));
  bandwidth_upgrade_run_loop.Run();
}

TEST_F(NearbyConnectionsTest, InitiateBandwidthUpgradeAfterAdvertisingFails) {
  FakeConnectionLifecycleListener fake_connection_life_cycle_listener;
  EndpointData endpoint_data = CreateEndpointData(1);

  StartAdvertising(fake_connection_life_cycle_listener, endpoint_data);

  // Requesting a bandwidth upgrade should fail.
  base::RunLoop bandwidth_upgrade_run_loop;
  nearby_connections_->InitiateBandwidthUpgrade(
      endpoint_data.remote_endpoint_id,
      base::BindLambdaForTesting([&](mojom::Status status) {
        EXPECT_EQ(mojom::Status::kOutOfOrderApiCall, status);
        bandwidth_upgrade_run_loop.Quit();
      }));
  bandwidth_upgrade_run_loop.Run();
}

TEST_F(NearbyConnectionsTest, InitiateBandwidthUpgradeAfterConnectionSucceeds) {
  // This endpoint starts discovery.
  FakeConnectionLifecycleListener fake_connection_life_cycle_listener;
  EndpointData endpoint_data = CreateEndpointData(1);
  StartAdvertising(fake_connection_life_cycle_listener, endpoint_data);

  // An incoming connection request is accepted at this endpoint.
  base::RunLoop accepted_run_loop;
  fake_connection_life_cycle_listener.accepted_cb =
      base::BindLambdaForTesting([&](const std::string& endpoint_id) {
        EXPECT_EQ(endpoint_data.remote_endpoint_id, endpoint_id);
        accepted_run_loop.Quit();
      });

  FakePayloadListener fake_payload_listener;
  AcceptConnection(fake_payload_listener, endpoint_data.remote_endpoint_id);
  accepted_run_loop.Run();

  // Requesting a bandwidth upgrade should succeed.
  base::RunLoop bandwidth_upgrade_run_loop;
  nearby_connections_->InitiateBandwidthUpgrade(
      endpoint_data.remote_endpoint_id,
      base::BindLambdaForTesting([&](mojom::Status status) {
        EXPECT_EQ(mojom::Status::kSuccess, status);
        bandwidth_upgrade_run_loop.Quit();
      }));
  bandwidth_upgrade_run_loop.Run();
}

TEST_F(NearbyConnectionsTest, ReceiveBytesPayload) {
  const std::vector<uint8_t> expected_payload(std::begin(kPayload),
                                              std::end(kPayload));
  FakeConnectionLifecycleListener fake_connection_life_cycle_listener;
  EndpointData endpoint_data = CreateEndpointData(1);
  StartAdvertising(fake_connection_life_cycle_listener, endpoint_data);

  base::RunLoop accepted_run_loop;
  fake_connection_life_cycle_listener.accepted_cb =
      base::BindLambdaForTesting([&](const std::string& endpoint_id) {
        EXPECT_EQ(endpoint_data.remote_endpoint_id, endpoint_id);
        accepted_run_loop.Quit();
      });

  FakePayloadListener fake_payload_listener;
  ClientProxy* client_proxy =
      AcceptConnection(fake_payload_listener, endpoint_data.remote_endpoint_id);
  accepted_run_loop.Run();

  base::RunLoop payload_run_loop;
  fake_payload_listener.payload_cb = base::BindLambdaForTesting(
      [&](const std::string& endpoint_id, mojom::PayloadPtr payload) {
        EXPECT_EQ(endpoint_data.remote_endpoint_id, endpoint_id);
        EXPECT_EQ(kPayloadId, payload->id);
        ASSERT_TRUE(payload->content->is_bytes());
        EXPECT_EQ(expected_payload, payload->content->get_bytes()->bytes);
        payload_run_loop.Quit();
      });

  client_proxy->OnPayload(
      endpoint_data.remote_endpoint_id,
      Payload(kPayloadId, ByteArrayFromMojom(expected_payload)));
  payload_run_loop.Run();
}

TEST_F(NearbyConnectionsTest, ReceiveFilePayload) {
  const std::vector<uint8_t> expected_payload(std::begin(kPayload),
                                              std::end(kPayload));
  FakeConnectionLifecycleListener fake_connection_life_cycle_listener;
  EndpointData endpoint_data = CreateEndpointData(1);
  StartAdvertising(fake_connection_life_cycle_listener, endpoint_data);

  base::RunLoop accepted_run_loop;
  fake_connection_life_cycle_listener.accepted_cb =
      base::BindLambdaForTesting([&](const std::string& endpoint_id) {
        EXPECT_EQ(endpoint_data.remote_endpoint_id, endpoint_id);
        accepted_run_loop.Quit();
      });

  FakePayloadListener fake_payload_listener;
  ClientProxy* client_proxy =
      AcceptConnection(fake_payload_listener, endpoint_data.remote_endpoint_id);
  accepted_run_loop.Run();

  base::FilePath path;
  EXPECT_TRUE(base::CreateTemporaryFile(&path));
  base::File output_file(path, base::File::Flags::FLAG_CREATE_ALWAYS |
                                   base::File::Flags::FLAG_WRITE);
  EXPECT_TRUE(output_file.IsValid());
  base::File input_file(
      path, base::File::Flags::FLAG_OPEN | base::File::Flags::FLAG_READ);
  EXPECT_TRUE(input_file.IsValid());

  base::RunLoop register_payload_run_loop;
  nearby_connections_->RegisterPayloadFile(
      kPayloadId, std::move(input_file), std::move(output_file),
      base::BindLambdaForTesting([&](mojom::Status status) {
        EXPECT_EQ(mojom::Status::kSuccess, status);
        register_payload_run_loop.Quit();
      }));
  register_payload_run_loop.Run();

  // Can start writing to OutputFile once registered.
  OutputFile core_output_file(kPayloadId);
  EXPECT_TRUE(
      core_output_file.Write(ByteArrayFromMojom(expected_payload)).Ok());
  EXPECT_TRUE(core_output_file.Flush().Ok());
  EXPECT_TRUE(core_output_file.Close().Ok());

  base::RunLoop payload_run_loop;
  fake_payload_listener.payload_cb = base::BindLambdaForTesting(
      [&](const std::string& endpoint_id, mojom::PayloadPtr payload) {
        EXPECT_EQ(endpoint_data.remote_endpoint_id, endpoint_id);
        EXPECT_EQ(kPayloadId, payload->id);
        ASSERT_TRUE(payload->content->is_file());

        base::File& file = payload->content->get_file()->file;
        std::vector<uint8_t> buffer(file.GetLength());
        EXPECT_TRUE(file.ReadAndCheck(/*offset=*/0, base::make_span(buffer)));
        EXPECT_EQ(expected_payload, buffer);

        payload_run_loop.Quit();
      });

  client_proxy->OnPayload(
      endpoint_data.remote_endpoint_id,
      Payload(kPayloadId, InputFile(kPayloadId, expected_payload.size())));
  payload_run_loop.Run();
}

TEST_F(NearbyConnectionsTest, ReceiveFilePayloadNotRegistered) {
  const std::vector<uint8_t> expected_payload(std::begin(kPayload),
                                              std::end(kPayload));
  FakeConnectionLifecycleListener fake_connection_life_cycle_listener;
  EndpointData endpoint_data = CreateEndpointData(1);
  StartAdvertising(fake_connection_life_cycle_listener, endpoint_data);

  base::RunLoop accepted_run_loop;
  fake_connection_life_cycle_listener.accepted_cb =
      base::BindLambdaForTesting([&](const std::string& endpoint_id) {
        EXPECT_EQ(endpoint_data.remote_endpoint_id, endpoint_id);
        accepted_run_loop.Quit();
      });

  FakePayloadListener fake_payload_listener;
  ClientProxy* client_proxy =
      AcceptConnection(fake_payload_listener, endpoint_data.remote_endpoint_id);
  accepted_run_loop.Run();

  fake_payload_listener.payload_cb = base::BindLambdaForTesting(
      [&](const std::string& endpoint_id, mojom::PayloadPtr payload) {
        NOTREACHED();
      });

  EXPECT_CALL(*service_controller_ptr_,
              CancelPayload(testing::_, testing::Eq(kPayloadId)))
      .WillOnce(testing::Return(Status{Status::kSuccess}));

  client_proxy->OnPayload(
      endpoint_data.remote_endpoint_id,
      Payload(kPayloadId, InputFile(kPayloadId, expected_payload.size())));

  // All file oepeartion will throw IOException.
  OutputFile core_output_file(kPayloadId);
  EXPECT_TRUE(core_output_file.Write(ByteArrayFromMojom(expected_payload))
                  .Raised(Exception::kIo));
  EXPECT_TRUE(core_output_file.Flush().Raised(Exception::kIo));
  EXPECT_TRUE(core_output_file.Close().Raised(Exception::kIo));
}

TEST_F(NearbyConnectionsTest, RegisterPayloadFileInvalid) {
  base::RunLoop register_payload_run_loop;
  nearby_connections_->RegisterPayloadFile(
      kPayloadId, base::File(), base::File(),
      base::BindLambdaForTesting([&](mojom::Status status) {
        EXPECT_EQ(mojom::Status::kError, status);
        register_payload_run_loop.Quit();
      }));
  register_payload_run_loop.Run();
}

TEST_F(NearbyConnectionsTest, ReceiveStreamPayload) {
  const std::vector<uint8_t> expected_payload(std::begin(kPayload),
                                              std::end(kPayload));
  FakeConnectionLifecycleListener fake_connection_life_cycle_listener;
  EndpointData endpoint_data = CreateEndpointData(1);
  StartAdvertising(fake_connection_life_cycle_listener, endpoint_data);

  base::RunLoop accepted_run_loop;
  fake_connection_life_cycle_listener.accepted_cb =
      base::BindLambdaForTesting([&](const std::string& endpoint_id) {
        EXPECT_EQ(endpoint_data.remote_endpoint_id, endpoint_id);
        accepted_run_loop.Quit();
      });

  FakePayloadListener fake_payload_listener;
  ClientProxy* client_proxy =
      AcceptConnection(fake_payload_listener, endpoint_data.remote_endpoint_id);
  accepted_run_loop.Run();

  fake_payload_listener.payload_cb = base::BindLambdaForTesting(
      [](const std::string& endpoint_id, mojom::PayloadPtr payload) {
        NOTREACHED();
      });

  EXPECT_CALL(*service_controller_ptr_,
              CancelPayload(testing::_, testing::Eq(kPayloadId)))
      .WillOnce(testing::Return(Status{Status::kSuccess}));

  testing::NiceMock<MockInputStream> input_stream;
  client_proxy->OnPayload(
      endpoint_data.remote_endpoint_id,
      Payload(kPayloadId,
              [&input_stream]() -> InputStream& { return input_stream; }));
}

}  // namespace connections
}  // namespace nearby
}  // namespace location
