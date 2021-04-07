// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/query_tiles/internal/logger_impl.h"

#include "base/strings/string_number_conversions.h"
#include "base/values.h"

namespace query_tiles {
namespace {

std::string FetcherStatusToString(TileInfoRequestStatus status) {
  switch (status) {
    case TileInfoRequestStatus::kInit:
      return "INITIAL";
    case TileInfoRequestStatus::kSuccess:
      return "SUCCESS";
    case TileInfoRequestStatus::kFailure:
      return "FAIL";
    case TileInfoRequestStatus::kShouldSuspend:
      return "SUSPEND";
    default:
      return "UNKNOWN";
  }
}

std::string GroupStatusToString(TileGroupStatus status) {
  switch (status) {
    case TileGroupStatus::kSuccess:
      return "SUCCESS";
    case TileGroupStatus::kUninitialized:
      return "UN_INIT";
    case TileGroupStatus::kNoTiles:
      return "NO_TILES";
    case TileGroupStatus::kFailureDbOperation:
      return "DB_FAIL";
    default:
      return "UNKNOWN";
  }
}

}  // namespace

LoggerImpl::LoggerImpl() = default;

LoggerImpl::~LoggerImpl() = default;

void LoggerImpl::SetLogSource(LogSource* source) {
  log_source_ = source;
}

void LoggerImpl::AddObserver(Observer* observer) {
  DCHECK(!observers_.HasObserver(observer));
  observers_.AddObserver(observer);
}

void LoggerImpl::RemoveObserver(Observer* observer) {
  DCHECK(observers_.HasObserver(observer));
  observers_.RemoveObserver(observer);
}

base::Value LoggerImpl::GetServiceStatus() {
  base::DictionaryValue result;
  if (!log_source_)
    return std::move(result);

  result.SetString("fetcherStatus",
                   FetcherStatusToString(log_source_->GetFetcherStatus()));
  result.SetString("groupStatus",
                   GroupStatusToString(log_source_->GetGroupStatus()));
  return std::move(result);
}

base::Value LoggerImpl::GetTileData() {
  base::DictionaryValue result;
  if (!log_source_)
    return std::move(result);
  auto* tile_group = log_source_->GetTileGroup();
  // (crbug.com/1101557): Make the format pretty with every field in TileGroup
  // explicitly appears in the DictValue.
  if (tile_group)
    result.SetString("groupInfo", tile_group->DebugString());
  return std::move(result);
}

void LoggerImpl::OnServiceStatusChanged() {
  if (!observers_.might_have_observers())
    return;
  base::Value service_status = GetServiceStatus();
  for (auto& observer : observers_)
    observer.OnServiceStatusChanged(service_status);
}

void LoggerImpl::OnTileDataAvailable() {
  if (!observers_.might_have_observers())
    return;
  base::Value tile_data = GetTileData();
  for (auto& observer : observers_)
    observer.OnTileDataAvailable(tile_data);
}

}  // namespace query_tiles
