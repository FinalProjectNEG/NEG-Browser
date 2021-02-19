// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROMEOS_SCANNING_SCANNER_H_
#define CHROMEOS_SCANNING_SCANNER_H_

#include <string>

#include "base/containers/flat_map.h"
#include "base/containers/flat_set.h"
#include "chromeos/chromeos_export.h"
#include "net/base/ip_address.h"

namespace chromeos {

// The type of protocol used to communicate with a scanner.
enum class CHROMEOS_EXPORT ScanProtocol {
  kUnknown,
  kEscl,           // eSCL protocol.
  kEscls,          // eSCLS protocol.
  kLegacyNetwork,  // Non-eSCL(S), legacy network protocol.
  kLegacyUsb       // Non-eSCL(S), legacy USB protocol.
};

struct CHROMEOS_EXPORT ScannerDeviceName {
  explicit ScannerDeviceName(const std::string& device_name);
  ScannerDeviceName(const std::string& device_name, bool usable);
  ~ScannerDeviceName();

  ScannerDeviceName(const ScannerDeviceName& scanner_device_name);
  ScannerDeviceName& operator=(const ScannerDeviceName& scanner_device_name);

  bool operator<(const ScannerDeviceName& other) const;
  bool operator==(const ScannerDeviceName& other) const;

  // The device name corresponding to the SANE backend, and therefore the
  // protocol, used to interact with the scanner.
  std::string device_name;

  // Signifies whether the device name can be used to interact with the scanner.
  // Device names are considered usable until proven otherwise (i.e. a device
  // name is marked as unusable when attempting to use it fails).
  bool usable = true;
};

struct CHROMEOS_EXPORT Scanner {
  Scanner();
  ~Scanner();

  Scanner(const Scanner& scanner);
  Scanner& operator=(const Scanner& scanner);

  // Name to display in a UI.
  std::string display_name;

  // Map of ScanProtocol to a set of corresponding ScannerDeviceNames that can
  // be used with the lorgnette D-Bus service. Clients are responsible for
  // selecting which device name to use.
  base::flat_map<ScanProtocol, base::flat_set<ScannerDeviceName>> device_names;

  // Known IP addresses for this scanner. Used to deduplicate network scanners
  // from multiple sources.
  base::flat_set<net::IPAddress> ip_addresses;
};

}  // namespace chromeos

#endif  // CHROMEOS_SCANNING_SCANNER_H_
