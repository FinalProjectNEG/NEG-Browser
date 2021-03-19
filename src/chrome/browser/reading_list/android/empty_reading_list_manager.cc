// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/reading_list/android/empty_reading_list_manager.h"

EmptyReadingListManager::EmptyReadingListManager() = default;

EmptyReadingListManager::~EmptyReadingListManager() = default;

void EmptyReadingListManager::AddObserver(Observer* observer) {}

void EmptyReadingListManager::RemoveObserver(Observer* observer) {}

const bookmarks::BookmarkNode* EmptyReadingListManager::Add(
    const GURL& url,
    const std::string& title) {
  return nullptr;
}

const bookmarks::BookmarkNode* EmptyReadingListManager::Get(
    const GURL& url) const {
  return nullptr;
}

const bookmarks::BookmarkNode* EmptyReadingListManager::GetNodeByID(
    int64_t id) const {
  return nullptr;
}

bool EmptyReadingListManager::IsReadingListBookmark(
    const bookmarks::BookmarkNode* node) const {
  return false;
}

void EmptyReadingListManager::Delete(const GURL& url) {}

const bookmarks::BookmarkNode* EmptyReadingListManager::GetRoot() const {
  return nullptr;
}

size_t EmptyReadingListManager::size() const {
  return 0u;
}

size_t EmptyReadingListManager::unread_size() const {
  return 0u;
}

void EmptyReadingListManager::SetReadStatus(const GURL& url, bool read) {}

bool EmptyReadingListManager::IsLoaded() const {
  return true;
}
