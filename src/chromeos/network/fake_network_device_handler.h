// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROMEOS_NETWORK_FAKE_NETWORK_DEVICE_HANDLER_H_
#define CHROMEOS_NETWORK_FAKE_NETWORK_DEVICE_HANDLER_H_

#include <string>
#include <vector>

#include "base/compiler_specific.h"
#include "base/component_export.h"
#include "base/macros.h"
#include "chromeos/network/network_device_handler.h"

namespace chromeos {

// This is a fake implementation which does nothing. Use this as a base class
// for concrete fake handlers.
class COMPONENT_EXPORT(CHROMEOS_NETWORK) FakeNetworkDeviceHandler
    : public NetworkDeviceHandler {
 public:
  FakeNetworkDeviceHandler();
  ~FakeNetworkDeviceHandler() override;

  // NetworkDeviceHandler overrides
  void GetDeviceProperties(
      const std::string& device_path,
      network_handler::ResultCallback callback) const override;

  void SetDeviceProperty(
      const std::string& device_path,
      const std::string& property_name,
      const base::Value& value,
      base::OnceClosure callback,
      network_handler::ErrorCallback error_callback) override;

  void RegisterCellularNetwork(
      const std::string& device_path,
      const std::string& network_id,
      base::OnceClosure callback,
      network_handler::ErrorCallback error_callback) override;

  void RequirePin(const std::string& device_path,
                  bool require_pin,
                  const std::string& pin,
                  base::OnceClosure callback,
                  network_handler::ErrorCallback error_callback) override;

  void EnterPin(const std::string& device_path,
                const std::string& pin,
                base::OnceClosure callback,
                network_handler::ErrorCallback error_callback) override;

  void UnblockPin(const std::string& device_path,
                  const std::string& puk,
                  const std::string& new_pin,
                  base::OnceClosure callback,
                  network_handler::ErrorCallback error_callback) override;

  void ChangePin(const std::string& device_path,
                 const std::string& old_pin,
                 const std::string& new_pin,
                 base::OnceClosure callback,
                 network_handler::ErrorCallback error_callback) override;

  void SetCellularAllowRoaming(bool allow_roaming) override;

  void SetUsbEthernetMacAddressSource(const std::string& source) override;

  void AddWifiWakeOnPacketConnection(
      const net::IPEndPoint& ip_endpoint,
      base::OnceClosure callback,
      network_handler::ErrorCallback error_callback) override;

  void AddWifiWakeOnPacketOfTypes(
      const std::vector<std::string>& types,
      base::OnceClosure callback,
      network_handler::ErrorCallback error_callback) override;

  void RemoveWifiWakeOnPacketConnection(
      const net::IPEndPoint& ip_endpoint,
      base::OnceClosure callback,
      network_handler::ErrorCallback error_callback) override;

  void RemoveWifiWakeOnPacketOfTypes(
      const std::vector<std::string>& types,
      base::OnceClosure callback,
      network_handler::ErrorCallback error_callback) override;

  void RemoveAllWifiWakeOnPacketConnections(
      base::OnceClosure callback,
      network_handler::ErrorCallback error_callback) override;

 private:
  DISALLOW_COPY_AND_ASSIGN(FakeNetworkDeviceHandler);
};

}  // namespace chromeos

#endif  // CHROMEOS_NETWORK_FAKE_NETWORK_DEVICE_HANDLER_H_
