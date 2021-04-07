// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/sync/model/model_type_store_base.h"

#include "components/sync/model_impl/in_memory_metadata_change_list.h"

namespace syncer {

// static
std::unique_ptr<MetadataChangeList>
ModelTypeStoreBase::WriteBatch::CreateMetadataChangeList() {
  return std::make_unique<InMemoryMetadataChangeList>();
}

ModelTypeStoreBase::WriteBatch::WriteBatch() {}

ModelTypeStoreBase::WriteBatch::~WriteBatch() {}

void ModelTypeStoreBase::WriteBatch::TakeMetadataChangesFrom(
    std::unique_ptr<MetadataChangeList> mcl) {
  static_cast<InMemoryMetadataChangeList*>(mcl.get())->TransferChangesTo(
      GetMetadataChangeList());
}

ModelTypeStoreBase::ModelTypeStoreBase() = default;

ModelTypeStoreBase::~ModelTypeStoreBase() = default;

}  // namespace syncer
