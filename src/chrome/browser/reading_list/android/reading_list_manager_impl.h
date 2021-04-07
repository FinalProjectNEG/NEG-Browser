// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_READING_LIST_ANDROID_READING_LIST_MANAGER_IMPL_H_
#define CHROME_BROWSER_READING_LIST_ANDROID_READING_LIST_MANAGER_IMPL_H_

#include "chrome/browser/reading_list/android/reading_list_manager.h"

#include <memory>

#include "components/reading_list/core/reading_list_model_observer.h"

class ReadingListModel;

// Implementation of ReadingListManager.
// 1. Holds a in memory bookmark node tree. Contains a folder root and reading
// list nodes as children. Only has one level of children.
// 2. Talk to reading list model, and sync with the in memory bookmark tree.
// 3. Talk to observers to report model change events.
class ReadingListManagerImpl : public ReadingListManager,
                               public ReadingListModelObserver {
 public:
  explicit ReadingListManagerImpl(ReadingListModel* reading_list_model);
  ~ReadingListManagerImpl() override;

 private:
  // ReadingListModelObserver overrides.
  void ReadingListModelLoaded(const ReadingListModel* model) override;

  // ReadingListManager implementation.
  void AddObserver(Observer* observer) override;
  void RemoveObserver(Observer* observer) override;
  const bookmarks::BookmarkNode* Add(const GURL& url,
                                     const std::string& title) override;
  const bookmarks::BookmarkNode* Get(const GURL& url) const override;
  const bookmarks::BookmarkNode* GetNodeByID(int64_t id) const override;
  bool IsReadingListBookmark(
      const bookmarks::BookmarkNode* node) const override;
  void Delete(const GURL& url) override;
  const bookmarks::BookmarkNode* GetRoot() const override;
  size_t size() const override;
  size_t unread_size() const override;
  void SetReadStatus(const GURL& url, bool read) override;
  bool IsLoaded() const override;

  // Finds the child in the bookmark tree by URL. Returns nullptr if not found.
  // Not recursive since the reading list bookmark tree only has a folder root
  // node and one level of children.
  bookmarks::BookmarkNode* FindBookmarkByURL(const GURL& url) const;

  void RemoveBookmark(const GURL& url);
  const bookmarks::BookmarkNode* AddBookmark(const ReadingListEntry* entry);

  // Contains reading list data, outlives this class.
  ReadingListModel* reading_list_model_;

  // The bookmark root for reading list articles.
  std::unique_ptr<bookmarks::BookmarkNode> root_;

  // Auto increment bookmark id. Will not be persisted and only used in memory.
  int64_t maximum_id_;

  // Whether the |reading_list_model_| is loaded.
  bool loaded_;

  base::ObserverList<Observer> observers_;
};

#endif  // CHROME_BROWSER_READING_LIST_ANDROID_READING_LIST_MANAGER_IMPL_H_
