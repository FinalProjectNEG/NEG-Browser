// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/offline_items_collection/core/filtered_offline_item_observer.h"
#include <utility>

namespace offline_items_collection {

FilteredOfflineItemObserver::FilteredOfflineItemObserver(
    OfflineContentProvider* provider)
    : provider_(provider) {
  provider_->AddObserver(this);
}

FilteredOfflineItemObserver::~FilteredOfflineItemObserver() {
  provider_->RemoveObserver(this);
}

void FilteredOfflineItemObserver::AddObserver(const ContentId& id,
                                              Observer* observer) {
  if (observers_.find(id) == observers_.end())
    observers_.insert(std::make_pair(id, std::make_unique<ObserverValue>()));

  observers_[id]->AddObserver(observer);
}

void FilteredOfflineItemObserver::RemoveObserver(const ContentId& id,
                                                 Observer* observer) {
  auto it = observers_.find(id);
  if (it == observers_.end())
    return;

  it->second->RemoveObserver(observer);

  if (!it->second->might_have_observers())
    observers_.erase(it);
}

void FilteredOfflineItemObserver::OnItemsAdded(
    const OfflineContentProvider::OfflineItemList& items) {}

void FilteredOfflineItemObserver::OnItemRemoved(const ContentId& id) {
  auto it = observers_.find(id);
  if (it == observers_.end())
    return;

  for (auto& observer : *(it->second))
    observer.OnItemRemoved(id);
}

void FilteredOfflineItemObserver::OnItemUpdated(
    const OfflineItem& item,
    const base::Optional<UpdateDelta>& update_delta) {
  auto it = observers_.find(item.id);
  if (it == observers_.end())
    return;

  for (auto& observer : *(it->second))
    observer.OnItemUpdated(item, update_delta);
}

}  // namespace offline_items_collection
