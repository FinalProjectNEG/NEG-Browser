// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/send_tab_to_self/target_device_info.h"

#include "base/feature_list.h"
#include "base/strings/strcat.h"
#include "components/send_tab_to_self/features.h"
#include "components/strings/grit/components_strings.h"
#include "components/sync_device_info/device_info.h"
#include "ui/base/l10n/l10n_util.h"

namespace {

std::string GetDeviceType(sync_pb::SyncEnums::DeviceType type) {
  int device_type_message_id = -1;

  switch (type) {
    case sync_pb::SyncEnums::TYPE_LINUX:
    case sync_pb::SyncEnums::TYPE_WIN:
    case sync_pb::SyncEnums::TYPE_CROS:
    case sync_pb::SyncEnums::TYPE_MAC:
      device_type_message_id = IDS_SHARING_DEVICE_TYPE_COMPUTER;
      device_type_message_id = IDS_SHARING_DEVICE_TYPE_COMPUTER;
      break;

    case sync_pb::SyncEnums::TYPE_UNSET:
    case sync_pb::SyncEnums::TYPE_OTHER:
      device_type_message_id = IDS_SHARING_DEVICE_TYPE_DEVICE;
      device_type_message_id = IDS_SHARING_DEVICE_TYPE_DEVICE;
      break;

    case sync_pb::SyncEnums::TYPE_PHONE:
      device_type_message_id = IDS_SHARING_DEVICE_TYPE_PHONE;
      device_type_message_id = IDS_SHARING_DEVICE_TYPE_PHONE;
      break;

    case sync_pb::SyncEnums::TYPE_TABLET:
      device_type_message_id = IDS_SHARING_DEVICE_TYPE_TABLET;
      device_type_message_id = IDS_SHARING_DEVICE_TYPE_TABLET;
      break;
  }

  return l10n_util::GetStringUTF8(device_type_message_id);
}

std::string CapitalizeWords(const std::string& sentence) {
  std::string capitalized_sentence;
  bool use_upper_case = true;
  for (char ch : sentence) {
    capitalized_sentence += (use_upper_case ? toupper(ch) : ch);
    use_upper_case = !isalpha(ch);
  }
  return capitalized_sentence;
}

}  // namespace

namespace send_tab_to_self {

TargetDeviceInfo::TargetDeviceInfo(
    const std::string& full_name,
    const std::string& short_name,
    const std::string& cache_guid,
    const sync_pb::SyncEnums::DeviceType device_type,
    base::Time last_updated_timestamp)
    : full_name(full_name),
      short_name(short_name),
      device_name(short_name),
      cache_guid(cache_guid),
      device_type(device_type),
      last_updated_timestamp(last_updated_timestamp) {}

TargetDeviceInfo::TargetDeviceInfo(const TargetDeviceInfo& other) = default;
TargetDeviceInfo::~TargetDeviceInfo() {}

bool TargetDeviceInfo::operator==(const TargetDeviceInfo& rhs) const {
  return this->full_name == rhs.full_name &&
         this->short_name == rhs.short_name &&
         this->device_name == rhs.device_name &&
         this->cache_guid == rhs.cache_guid &&
         this->device_type == rhs.device_type &&
         this->last_updated_timestamp == rhs.last_updated_timestamp;
}

SharingDeviceNames GetSharingDeviceNames(const syncer::DeviceInfo* device) {
  DCHECK(device);
  std::string model = device->model_name();

  // 1. Skip renaming for M78- devices where HardwareInfo is not available.
  // 2. Skip renaming if client_name is high quality i.e. not equals to model.
  if (model.empty() || model != device->client_name())
    return {device->client_name(), device->client_name()};

  std::string manufacturer = CapitalizeWords(device->manufacturer_name());
  sync_pb::SyncEnums::DeviceType type = device->device_type();

  // For chromeOS, return manufacturer + model.
  if (type == sync_pb::SyncEnums::TYPE_CROS) {
    std::string name = base::StrCat({manufacturer, " ", model});
    return {name, name};
  }

  // Internal names of Apple devices are formatted as MacbookPro2,3 or
  // iPhone2,1 or Ipad4,1.
  if (manufacturer == "Apple Inc.")
    return {model, model.substr(0, model.find_first_of("0123456789,"))};

  std::string short_name =
      base::StrCat({manufacturer, " ", GetDeviceType(type)});
  std::string full_name = base::StrCat({short_name, " ", model});
  return {full_name, short_name};
}

}  // namespace send_tab_to_self
