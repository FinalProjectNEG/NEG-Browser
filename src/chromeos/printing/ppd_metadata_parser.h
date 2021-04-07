// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file declares parsing functions for use with PPD metadata.
// The PpdMetadataManager class is the primary consumer.
//
// Each Parse*() function promises these invariants:
// 1. they attempt to parse as much JSON as possible (returning
//    all relevant data that can be reasonably extracted),
// 2. they return base::nullopt on irrecoverable parse error, and
// 3. they never return a non-nullopt value that unwraps into an empty
//    container.
//
// Googlers: you may consult the primary documentation for PPD metadata
// at go/cros-printing:ppd-metadata

#include <string>
#include <vector>

#include "base/containers/flat_map.h"
#include "base/optional.h"
#include "base/strings/string_piece_forward.h"
#include "base/version.h"
#include "chromeos/chromeos_export.h"

#ifndef CHROMEOS_PRINTING_PPD_METADATA_PARSER_H_
#define CHROMEOS_PRINTING_PPD_METADATA_PARSER_H_

namespace chromeos {

// Defines the limitations on when we show a particular PPD.
struct Restrictions {
  Restrictions();
  ~Restrictions();
  Restrictions(const Restrictions&);
  Restrictions& operator=(const Restrictions&);

  base::Optional<base::Version> min_milestone;
  base::Optional<base::Version> max_milestone;
};

struct CHROMEOS_EXPORT ReverseIndexLeaf {
  std::string manufacturer;
  std::string model;
};

// A ParsedPrinter is a value parsed from printers metadata.
struct CHROMEOS_EXPORT ParsedPrinter {
  ParsedPrinter();
  ~ParsedPrinter();
  ParsedPrinter(const ParsedPrinter&);
  ParsedPrinter& operator=(const ParsedPrinter&);

  std::string user_visible_printer_name;
  std::string effective_make_and_model;
  Restrictions restrictions;
};

// A single leaf value parsed from a forward index.
struct CHROMEOS_EXPORT ParsedIndexLeaf {
  ParsedIndexLeaf();
  ~ParsedIndexLeaf();
  ParsedIndexLeaf(const ParsedIndexLeaf&);
  ParsedIndexLeaf& operator=(const ParsedIndexLeaf&);

  std::string ppd_basename;
  Restrictions restrictions;
  std::string license;
};

// A collection of values parsed from a forward index.
// Corresponds to one effective-make-and-model string.
struct CHROMEOS_EXPORT ParsedIndexValues {
  ParsedIndexValues();
  ~ParsedIndexValues();
  ParsedIndexValues(const ParsedIndexValues&);
  ParsedIndexValues& operator=(const ParsedIndexValues&);

  std::vector<ParsedIndexLeaf> values;
};

// Maps manufacturer names to basenames of printers metadata.
using ParsedManufacturers = base::flat_map<std::string, std::string>;

using ParsedPrinters = std::vector<ParsedPrinter>;

// *  Keys are effective-make-and-model strings.
// *  Values collect information corresponding to each
//    effective-make-and-model string - chiefly information about
//    individual PPDs.
// *  Googlers, see also: go/cros-printing:ppd-metadata#index
using ParsedIndex = base::flat_map<std::string, ParsedIndexValues>;

// Maps USB product IDs to effective-make-and-model strings.
using ParsedUsbIndex = base::flat_map<int, std::string>;

// Maps USB vendor IDs to manufacturer names.
using ParsedUsbVendorIdMap = base::flat_map<int, std::string>;

// Keyed on effective-make-and-model strings.
using ParsedReverseIndex = base::flat_map<std::string, ReverseIndexLeaf>;

// Parses |locales_json| and returns a list of locales.
CHROMEOS_EXPORT base::Optional<std::vector<std::string>> ParseLocales(
    base::StringPiece locales_json);

// Parses |manufacturers_json| and returns the parsed map type.
CHROMEOS_EXPORT base::Optional<ParsedManufacturers> ParseManufacturers(
    base::StringPiece manufacturers_json);

// Parses |printers_json| and returns the parsed map type.
CHROMEOS_EXPORT base::Optional<ParsedPrinters> ParsePrinters(
    base::StringPiece printers_json);

// Parses |forward_index_json| and returns the parsed map type.
CHROMEOS_EXPORT base::Optional<ParsedIndex> ParseForwardIndex(
    base::StringPiece forward_index_json);

// Parses |usb_index_json| and returns a map of USB product IDs to
// effective-make-and-model strings.
CHROMEOS_EXPORT base::Optional<ParsedUsbIndex> ParseUsbIndex(
    base::StringPiece usb_index_json);

// Parses |usb_vendor_id_map_json| and returns a map of USB vendor IDs
// to manufacturer names.
CHROMEOS_EXPORT base::Optional<ParsedUsbVendorIdMap> ParseUsbVendorIdMap(
    base::StringPiece usb_vendor_id_map_json);

// Parses |reverse_index_json| and returns the parsed map type.
CHROMEOS_EXPORT base::Optional<ParsedReverseIndex> ParseReverseIndex(
    base::StringPiece reverse_index_json);

}  // namespace chromeos
#endif  // CHROMEOS_PRINTING_PPD_METADATA_PARSER_H_
