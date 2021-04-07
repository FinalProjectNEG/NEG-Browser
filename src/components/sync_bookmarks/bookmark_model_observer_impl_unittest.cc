// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/sync_bookmarks/bookmark_model_observer_impl.h"

#include <algorithm>
#include <list>
#include <map>
#include <memory>
#include <utility>
#include <vector>

#include "base/bind_helpers.h"
#include "base/strings/utf_string_conversions.h"
#include "base/test/mock_callback.h"
#include "base/test/scoped_feature_list.h"
#include "components/bookmarks/browser/bookmark_model.h"
#include "components/bookmarks/test/test_bookmark_client.h"
#include "components/favicon_base/favicon_types.h"
#include "components/sync/base/time.h"
#include "components/sync/base/unique_position.h"
#include "components/sync/driver/sync_driver_switches.h"
#include "components/sync_bookmarks/bookmark_specifics_conversions.h"
#include "components/sync_bookmarks/switches.h"
#include "components/sync_bookmarks/synced_bookmark_tracker.h"
#include "components/undo/bookmark_undo_service.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/skia/include/core/SkBitmap.h"
#include "ui/gfx/image/image.h"

namespace sync_bookmarks {

namespace {

using testing::ElementsAre;
using testing::Eq;
using testing::IsEmpty;
using testing::IsNull;
using testing::Ne;
using testing::NiceMock;
using testing::NotNull;
using testing::UnorderedElementsAre;

const char kBookmarkBarId[] = "bookmark_bar_id";
const char kBookmarkBarTag[] = "bookmark_bar";
const char kOtherBookmarksId[] = "other_bookmarks_id";
const char kOtherBookmarksTag[] = "other_bookmarks";
const char kMobileBookmarksId[] = "synced_bookmarks_id";
const char kMobileBookmarksTag[] = "synced_bookmarks";
const size_t kMaxEntries = 1000;

// Matches |arg| of type SyncedBookmarkTracker::Entity*.
MATCHER_P(HasBookmarkNode, node, "") {
  return arg->bookmark_node() == node;
}

// Returns a single-color 16x16 image using |color|.
gfx::Image CreateTestImage(SkColor color) {
  SkBitmap bitmap;
  bitmap.allocN32Pixels(16, 16);
  bitmap.eraseColor(color);
  return gfx::Image::CreateFrom1xBitmap(bitmap);
}

// Extension of TestBookmarkClient with basic functionality to test favicon
// loading.
class TestBookmarkClientWithFavicon : public bookmarks::TestBookmarkClient {
 public:
  // Mimics the completion of a previously-triggered GetFaviconImageForPageURL()
  // call for |page_url|, usually invoked by BookmarkModel. Returns false if no
  // such a call is pending completion. The completion returns a favicon with
  // URL |icon_url| and a single-color 16x16 image using |color|.
  bool SimulateFaviconLoaded(const GURL& page_url,
                             const GURL& icon_url,
                             SkColor color) {
    if (requests_per_page_url_[page_url].empty()) {
      return false;
    }

    favicon_base::FaviconImageCallback callback =
        std::move(requests_per_page_url_[page_url].front());
    requests_per_page_url_[page_url].pop_front();

    favicon_base::FaviconImageResult result;
    result.image = CreateTestImage(color);
    result.icon_url = icon_url;
    std::move(callback).Run(result);
    return true;
  }

  // Mimics the completion of a previously-triggered GetFaviconImageForPageURL()
  // call for |page_url|, usually invoked by BookmarkModel. Returns false if no
  // such a call is pending completion. The completion returns an empty image
  // for the favicon.
  bool SimulateEmptyFaviconLoaded(const GURL& page_url) {
    if (requests_per_page_url_[page_url].empty()) {
      return false;
    }

    favicon_base::FaviconImageCallback callback =
        std::move(requests_per_page_url_[page_url].front());
    requests_per_page_url_[page_url].pop_front();

    std::move(callback).Run(favicon_base::FaviconImageResult());
    return true;
  }

  // bookmarks::TestBookmarkClient implementation.
  base::CancelableTaskTracker::TaskId GetFaviconImageForPageURL(
      const GURL& page_url,
      favicon_base::FaviconImageCallback callback,
      base::CancelableTaskTracker* tracker) override {
    requests_per_page_url_[page_url].push_back(std::move(callback));
    return next_task_id_++;
  }

 private:
  base::CancelableTaskTracker::TaskId next_task_id_ = 1;
  std::map<GURL, std::list<favicon_base::FaviconImageCallback>>
      requests_per_page_url_;
};

class BookmarkModelObserverImplTest : public testing::Test {
 public:
  BookmarkModelObserverImplTest()
      : bookmark_tracker_(
            SyncedBookmarkTracker::CreateEmpty(sync_pb::ModelTypeState())),
        observer_(nudge_for_commit_closure_.Get(),
                  /*on_bookmark_model_being_deleted_closure=*/base::DoNothing(),
                  bookmark_tracker_.get()),
        bookmark_model_(bookmarks::TestBookmarkClient::CreateModelWithClient(
            std::make_unique<TestBookmarkClientWithFavicon>())) {
    bookmark_model_->AddObserver(&observer_);
    sync_pb::EntitySpecifics specifics;
    specifics.mutable_bookmark()->set_legacy_canonicalized_title(
        kBookmarkBarTag);
    bookmark_tracker_->Add(
        /*bookmark_node=*/bookmark_model()->bookmark_bar_node(),
        /*sync_id=*/kBookmarkBarId,
        /*server_version=*/0, /*creation_time=*/base::Time::Now(),
        syncer::UniquePosition::InitialPosition(
            syncer::UniquePosition::RandomSuffix())
            .ToProto(),
        specifics);
    specifics.mutable_bookmark()->set_legacy_canonicalized_title(
        kOtherBookmarksTag);
    bookmark_tracker_->Add(
        /*bookmark_node=*/bookmark_model()->other_node(),
        /*sync_id=*/kOtherBookmarksId,
        /*server_version=*/0, /*creation_time=*/base::Time::Now(),
        syncer::UniquePosition::InitialPosition(
            syncer::UniquePosition::RandomSuffix())
            .ToProto(),
        specifics);
    specifics.mutable_bookmark()->set_legacy_canonicalized_title(
        kMobileBookmarksTag);
    bookmark_tracker_->Add(
        /*bookmark_node=*/bookmark_model()->mobile_node(),
        /*sync_id=*/kMobileBookmarksId,
        /*server_version=*/0, /*creation_time=*/base::Time::Now(),
        syncer::UniquePosition::InitialPosition(
            syncer::UniquePosition::RandomSuffix())
            .ToProto(),
        specifics);
  }

  ~BookmarkModelObserverImplTest() {
    bookmark_model_->RemoveObserver(&observer_);
  }

  void SimulateCommitResponseForAllLocalChanges() {
    for (const SyncedBookmarkTracker::Entity* entity :
         bookmark_tracker()->GetEntitiesWithLocalChanges(kMaxEntries)) {
      const std::string id = entity->metadata()->server_id();
      // Don't simulate change in id for simplicity.
      bookmark_tracker()->UpdateUponCommitResponse(
          entity, id,
          /*server_version=*/1,
          /*acked_sequence_number=*/entity->metadata()->sequence_number());
    }
  }

  syncer::UniquePosition PositionOf(
      const bookmarks::BookmarkNode* bookmark_node) {
    const SyncedBookmarkTracker::Entity* entity =
        bookmark_tracker()->GetEntityForBookmarkNode(bookmark_node);
    return syncer::UniquePosition::FromProto(
        entity->metadata()->unique_position());
  }

  bookmarks::BookmarkModel* bookmark_model() { return bookmark_model_.get(); }
  SyncedBookmarkTracker* bookmark_tracker() { return bookmark_tracker_.get(); }
  BookmarkModelObserverImpl* observer() { return &observer_; }
  base::MockCallback<base::RepeatingClosure>* nudge_for_commit_closure() {
    return &nudge_for_commit_closure_;
  }
  TestBookmarkClientWithFavicon* bookmark_client() {
    return static_cast<TestBookmarkClientWithFavicon*>(
        bookmark_model_->client());
  }

 private:
  NiceMock<base::MockCallback<base::RepeatingClosure>>
      nudge_for_commit_closure_;
  std::unique_ptr<SyncedBookmarkTracker> bookmark_tracker_;
  BookmarkModelObserverImpl observer_;
  std::unique_ptr<bookmarks::BookmarkModel> bookmark_model_;
};

TEST_F(BookmarkModelObserverImplTest,
       BookmarkAddedShouldPutInTheTrackerAndNudgeForCommit) {
  const std::string kTitle = "title";
  const std::string kUrl = "http://www.url.com";

  EXPECT_CALL(*nudge_for_commit_closure(), Run());
  const bookmarks::BookmarkNode* bookmark_bar_node =
      bookmark_model()->bookmark_bar_node();
  const bookmarks::BookmarkNode* bookmark_node = bookmark_model()->AddURL(
      /*parent=*/bookmark_bar_node, /*index=*/0, base::UTF8ToUTF16(kTitle),
      GURL(kUrl));

  EXPECT_THAT(bookmark_tracker()->TrackedEntitiesCountForTest(), 4U);

  std::vector<const SyncedBookmarkTracker::Entity*> local_changes =
      bookmark_tracker()->GetEntitiesWithLocalChanges(kMaxEntries);
  ASSERT_THAT(local_changes.size(), 1U);
  EXPECT_THAT(local_changes[0]->bookmark_node(), Eq(bookmark_node));
  EXPECT_THAT(local_changes[0]->metadata()->server_id(),
              Eq(bookmark_node->guid()));
}

TEST_F(BookmarkModelObserverImplTest,
       BookmarkChangedShouldUpdateTheTrackerAndNudgeForCommit) {
  const std::string kTitle1 = "title1";
  const std::string kUrl1 = "http://www.url1.com";
  const std::string kNewUrl1 = "http://www.new-url1.com";
  const std::string kTitle2 = "title2";
  const std::string kUrl2 = "http://www.url2.com";
  const std::string kNewTitle2 = "new_title2";

  const bookmarks::BookmarkNode* bookmark_bar_node =
      bookmark_model()->bookmark_bar_node();
  const bookmarks::BookmarkNode* bookmark_node1 = bookmark_model()->AddURL(
      /*parent=*/bookmark_bar_node, /*index=*/0, base::UTF8ToUTF16(kTitle1),
      GURL(kUrl1));
  const bookmarks::BookmarkNode* bookmark_node2 = bookmark_model()->AddURL(
      /*parent=*/bookmark_bar_node, /*index=*/0, base::UTF8ToUTF16(kTitle2),
      GURL(kUrl2));
  // Both bookmarks should be tracked now.
  ASSERT_THAT(bookmark_tracker()->TrackedEntitiesCountForTest(), 5U);
  // There should be two local changes now for both entities.
  ASSERT_THAT(
      bookmark_tracker()->GetEntitiesWithLocalChanges(kMaxEntries).size(), 2U);

  SimulateCommitResponseForAllLocalChanges();

  // There should be no local changes now.
  ASSERT_TRUE(
      bookmark_tracker()->GetEntitiesWithLocalChanges(kMaxEntries).empty());

  // Now update the title of the 2nd node.
  EXPECT_CALL(*nudge_for_commit_closure(), Run());
  bookmark_model()->SetTitle(bookmark_node2, base::UTF8ToUTF16(kNewTitle2));
  // Node 2 should be in the local changes list.
  EXPECT_THAT(bookmark_tracker()->GetEntitiesWithLocalChanges(kMaxEntries),
              ElementsAre(HasBookmarkNode(bookmark_node2)));

  // Now update the url of the 1st node.
  EXPECT_CALL(*nudge_for_commit_closure(), Run());
  bookmark_model()->SetURL(bookmark_node1, GURL(kNewUrl1));

  // Node 1 and 2 should be in the local changes list.
  EXPECT_THAT(bookmark_tracker()->GetEntitiesWithLocalChanges(kMaxEntries),
              UnorderedElementsAre(HasBookmarkNode(bookmark_node1),
                                   HasBookmarkNode(bookmark_node2)));

  // Now update metainfo of the 1st node.
  EXPECT_CALL(*nudge_for_commit_closure(), Run());
  bookmark_model()->SetNodeMetaInfo(bookmark_node1, "key", "value");
}

TEST_F(BookmarkModelObserverImplTest,
       BookmarkMovedShouldUpdateTheTrackerAndNudgeForCommit) {
  // Build this structure:
  // bookmark_bar
  //  |- folder1
  //      |- bookmark1
  const GURL kUrl("http://www.url1.com");

  const bookmarks::BookmarkNode* bookmark_bar_node =
      bookmark_model()->bookmark_bar_node();
  const bookmarks::BookmarkNode* folder1_node = bookmark_model()->AddFolder(
      /*parent=*/bookmark_bar_node, /*index=*/0, base::UTF8ToUTF16("folder1"));
  const bookmarks::BookmarkNode* bookmark1_node = bookmark_model()->AddURL(
      /*parent=*/folder1_node, /*index=*/0, base::UTF8ToUTF16("bookmark1"),
      kUrl);

  // Verify number of entities local changes. Should be the same as number of
  // new nodes.
  ASSERT_THAT(
      bookmark_tracker()->GetEntitiesWithLocalChanges(kMaxEntries).size(), 2U);

  // All bookmarks should be tracked now.
  ASSERT_THAT(bookmark_tracker()->TrackedEntitiesCountForTest(), 5U);

  SimulateCommitResponseForAllLocalChanges();

  // There should be no local changes now.
  ASSERT_TRUE(
      bookmark_tracker()->GetEntitiesWithLocalChanges(kMaxEntries).empty());

  // Now change it to this structure.
  // Build this structure:
  // bookmark_bar
  //  |- bookmark1
  //  |- folder1

  EXPECT_CALL(*nudge_for_commit_closure(), Run());
  bookmark_model()->Move(bookmark1_node, bookmark_bar_node, 0);
  EXPECT_TRUE(PositionOf(bookmark1_node).LessThan(PositionOf(folder1_node)));
}

TEST_F(BookmarkModelObserverImplTest,
       ReorderChildrenShouldUpdateTheTrackerAndNudgeForCommit) {
  const std::string kTitle = "title";
  const std::string kUrl = "http://www.url.com";

  // Build this structure:
  // bookmark_bar
  //  |- node0
  //  |- node1
  //  |- node2
  //  |- node3
  const bookmarks::BookmarkNode* bookmark_bar_node =
      bookmark_model()->bookmark_bar_node();
  std::vector<const bookmarks::BookmarkNode*> nodes;
  for (size_t i = 0; i < 4; ++i) {
    nodes.push_back(bookmark_model()->AddURL(
        /*parent=*/bookmark_bar_node, /*index=*/i, base::UTF8ToUTF16(kTitle),
        GURL(kUrl)));
  }

  // Verify number of entities local changes. Should be the same as number of
  // new nodes.
  ASSERT_THAT(
      bookmark_tracker()->GetEntitiesWithLocalChanges(kMaxEntries).size(), 4U);

  // All bookmarks should be tracked now.
  ASSERT_THAT(bookmark_tracker()->TrackedEntitiesCountForTest(), 7U);

  SimulateCommitResponseForAllLocalChanges();

  // Reorder it to be:
  // bookmark_bar
  //  |- node1
  //  |- node3
  //  |- node0
  //  |- node2
  bookmark_model()->ReorderChildren(bookmark_bar_node,
                                    {nodes[1], nodes[3], nodes[0], nodes[2]});
  EXPECT_TRUE(PositionOf(nodes[1]).LessThan(PositionOf(nodes[3])));
  EXPECT_TRUE(PositionOf(nodes[3]).LessThan(PositionOf(nodes[0])));
  EXPECT_TRUE(PositionOf(nodes[0]).LessThan(PositionOf(nodes[2])));

  // All 4 nodes should have local changes to commit.
  EXPECT_THAT(bookmark_tracker()->GetEntitiesWithLocalChanges(kMaxEntries),
              UnorderedElementsAre(
                  HasBookmarkNode(nodes[0]), HasBookmarkNode(nodes[1]),
                  HasBookmarkNode(nodes[2]), HasBookmarkNode(nodes[3])));
}

TEST_F(BookmarkModelObserverImplTest,
       BookmarkRemovalShouldUpdateTheTrackerAndNudgeForCommit) {
  // Build this structure:
  // bookmark_bar
  //  |- folder1
  //      |- bookmark1
  //      |- folder2
  //          |- bookmark2
  //          |- bookmark3

  // and then delete folder2.
  const GURL kUrl("http://www.url1.com");

  const bookmarks::BookmarkNode* bookmark_bar_node =
      bookmark_model()->bookmark_bar_node();
  const bookmarks::BookmarkNode* folder1_node = bookmark_model()->AddFolder(
      /*parent=*/bookmark_bar_node, /*index=*/0, base::UTF8ToUTF16("folder1"));
  const bookmarks::BookmarkNode* bookmark1_node = bookmark_model()->AddURL(
      /*parent=*/folder1_node, /*index=*/0, base::UTF8ToUTF16("bookmark1"),
      kUrl);
  const bookmarks::BookmarkNode* folder2_node = bookmark_model()->AddFolder(
      /*parent=*/folder1_node, /*index=*/1, base::UTF8ToUTF16("folder2"));
  const bookmarks::BookmarkNode* bookmark2_node = bookmark_model()->AddURL(
      /*parent=*/folder2_node, /*index=*/0, base::UTF8ToUTF16("bookmark2"),
      kUrl);
  const bookmarks::BookmarkNode* bookmark3_node = bookmark_model()->AddURL(
      /*parent=*/folder2_node, /*index=*/1, base::UTF8ToUTF16("bookmark3"),
      kUrl);

  // All bookmarks should be tracked now.
  ASSERT_THAT(bookmark_tracker()->TrackedEntitiesCountForTest(), 8U);

  SimulateCommitResponseForAllLocalChanges();

  // There should be no local changes now.
  ASSERT_TRUE(
      bookmark_tracker()->GetEntitiesWithLocalChanges(kMaxEntries).empty());

  const SyncedBookmarkTracker::Entity* folder2_entity =
      bookmark_tracker()->GetEntityForBookmarkNode(folder2_node);
  const SyncedBookmarkTracker::Entity* bookmark2_entity =
      bookmark_tracker()->GetEntityForBookmarkNode(bookmark2_node);
  const SyncedBookmarkTracker::Entity* bookmark3_entity =
      bookmark_tracker()->GetEntityForBookmarkNode(bookmark3_node);

  ASSERT_FALSE(folder2_entity->metadata()->is_deleted());
  ASSERT_FALSE(bookmark2_entity->metadata()->is_deleted());
  ASSERT_FALSE(bookmark3_entity->metadata()->is_deleted());

  const std::string& folder2_entity_id =
      folder2_entity->metadata()->server_id();
  const std::string& bookmark2_entity_id =
      bookmark2_entity->metadata()->server_id();
  const std::string& bookmark3_entity_id =
      bookmark3_entity->metadata()->server_id();
  // Delete folder2.
  EXPECT_CALL(*nudge_for_commit_closure(), Run());
  bookmark_model()->Remove(folder2_node);

  // folder2, bookmark2, and bookmark3 should be marked deleted.
  EXPECT_TRUE(bookmark_tracker()
                  ->GetEntityForSyncId(folder2_entity_id)
                  ->metadata()
                  ->is_deleted());
  EXPECT_TRUE(bookmark_tracker()
                  ->GetEntityForSyncId(bookmark2_entity_id)
                  ->metadata()
                  ->is_deleted());
  EXPECT_TRUE(bookmark_tracker()
                  ->GetEntityForSyncId(bookmark3_entity_id)
                  ->metadata()
                  ->is_deleted());

  // folder2, bookmark2, and bookmark3 should be in the local changes to be
  // committed and folder2 deletion should be the last one (after all children
  // deletions).
  EXPECT_THAT(
      bookmark_tracker()->GetEntitiesWithLocalChanges(kMaxEntries),
      ElementsAre(bookmark_tracker()->GetEntityForSyncId(bookmark2_entity_id),
                  bookmark_tracker()->GetEntityForSyncId(bookmark3_entity_id),
                  bookmark_tracker()->GetEntityForSyncId(folder2_entity_id)));

  // folder1 and bookmark1 are still tracked.
  EXPECT_TRUE(bookmark_tracker()->GetEntityForBookmarkNode(folder1_node));
  EXPECT_TRUE(bookmark_tracker()->GetEntityForBookmarkNode(bookmark1_node));
}

TEST_F(BookmarkModelObserverImplTest,
       BookmarkCreationAndRemovalShouldRequireTwoCommitResponsesBeforeRemoval) {
  const bookmarks::BookmarkNode* bookmark_bar_node =
      bookmark_model()->bookmark_bar_node();
  const bookmarks::BookmarkNode* folder_node = bookmark_model()->AddFolder(
      /*parent=*/bookmark_bar_node, /*index=*/0, base::UTF8ToUTF16("folder"));

  // Node should be tracked now.
  ASSERT_THAT(bookmark_tracker()->TrackedEntitiesCountForTest(), 4U);
  const SyncedBookmarkTracker::Entity* entity =
      bookmark_tracker()->GetEntityForBookmarkNode(folder_node);
  const std::string id = entity->metadata()->server_id();
  ASSERT_THAT(
      bookmark_tracker()->GetEntitiesWithLocalChanges(kMaxEntries).size(), 1U);

  bookmark_tracker()->MarkCommitMayHaveStarted(entity);

  // Remove the folder.
  bookmark_model()->Remove(folder_node);

  // Simulate a commit response for the first commit request (the creation).
  // Don't simulate change in id for simplicity.
  bookmark_tracker()->UpdateUponCommitResponse(entity, id,
                                               /*server_version=*/1,
                                               /*acked_sequence_number=*/1);

  // There should still be one local change (the deletion).
  EXPECT_THAT(
      bookmark_tracker()->GetEntitiesWithLocalChanges(kMaxEntries).size(), 1U);

  // Entity is still tracked.
  EXPECT_THAT(bookmark_tracker()->TrackedEntitiesCountForTest(), 4U);

  // Commit the deletion.
  bookmark_tracker()->UpdateUponCommitResponse(entity, id,
                                               /*server_version=*/2,
                                               /*acked_sequence_number=*/2);
  // Entity should have been dropped.
  EXPECT_THAT(bookmark_tracker()->TrackedEntitiesCountForTest(), 3U);
}

TEST_F(BookmarkModelObserverImplTest,
       BookmarkCreationAndRemovalBeforeCommitRequestShouldBeRemovedDirectly) {
  const bookmarks::BookmarkNode* bookmark_bar_node =
      bookmark_model()->bookmark_bar_node();
  const bookmarks::BookmarkNode* folder_node = bookmark_model()->AddFolder(
      /*parent=*/bookmark_bar_node, /*index=*/0, base::UTF8ToUTF16("folder"));

  // Node should be tracked now.
  ASSERT_THAT(bookmark_tracker()->TrackedEntitiesCountForTest(), 4U);
  const std::string id = bookmark_tracker()
                             ->GetEntityForBookmarkNode(folder_node)
                             ->metadata()
                             ->server_id();
  ASSERT_THAT(
      bookmark_tracker()->GetEntitiesWithLocalChanges(kMaxEntries).size(), 1U);

  // Remove the folder.
  bookmark_model()->Remove(folder_node);

  // Entity should have been dropped.
  EXPECT_THAT(bookmark_tracker()->TrackedEntitiesCountForTest(), 3U);
}

TEST_F(BookmarkModelObserverImplTest, ShouldPositionSiblings) {
  const std::string kTitle = "title";
  const std::string kUrl = "http://www.url.com";

  // Build this structure:
  // bookmark_bar
  //  |- node1
  //  |- node2
  // Expectation:
  //  p1 < p2

  const bookmarks::BookmarkNode* bookmark_bar_node =
      bookmark_model()->bookmark_bar_node();
  const bookmarks::BookmarkNode* bookmark_node1 = bookmark_model()->AddURL(
      /*parent=*/bookmark_bar_node, /*index=*/0, base::UTF8ToUTF16(kTitle),
      GURL(kUrl));

  const bookmarks::BookmarkNode* bookmark_node2 = bookmark_model()->AddURL(
      /*parent=*/bookmark_bar_node, /*index=*/1, base::UTF8ToUTF16(kTitle),
      GURL(kUrl));

  EXPECT_TRUE(PositionOf(bookmark_node1).LessThan(PositionOf(bookmark_node2)));

  // Now insert node3 at index 1 to build this structure:
  // bookmark_bar
  //  |- node1
  //  |- node3
  //  |- node2
  // Expectation:
  //  p1 < p2 (still holds)
  //  p1 < p3
  //  p3 < p2

  const bookmarks::BookmarkNode* bookmark_node3 = bookmark_model()->AddURL(
      /*parent=*/bookmark_bar_node, /*index=*/1, base::UTF8ToUTF16(kTitle),
      GURL(kUrl));
  EXPECT_THAT(bookmark_tracker()->TrackedEntitiesCountForTest(), Eq(6U));

  EXPECT_TRUE(PositionOf(bookmark_node1).LessThan(PositionOf(bookmark_node2)));
  EXPECT_TRUE(PositionOf(bookmark_node1).LessThan(PositionOf(bookmark_node3)));
  EXPECT_TRUE(PositionOf(bookmark_node3).LessThan(PositionOf(bookmark_node2)));
}

TEST_F(BookmarkModelObserverImplTest, ShouldNotSyncUnsyncableBookmarks) {
  auto client = std::make_unique<bookmarks::TestBookmarkClient>();
  bookmarks::BookmarkNode* managed_node = client->EnableManagedNode();

  std::unique_ptr<bookmarks::BookmarkModel> model =
      bookmarks::TestBookmarkClient::CreateModelWithClient(std::move(client));

  std::unique_ptr<SyncedBookmarkTracker> bookmark_tracker =
      SyncedBookmarkTracker::CreateEmpty(sync_pb::ModelTypeState());
  sync_pb::EntitySpecifics specifics;
  specifics.mutable_bookmark()->set_legacy_canonicalized_title(kBookmarkBarTag);
  bookmark_tracker->Add(
      /*bookmark_node=*/model->bookmark_bar_node(),
      /*sync_id=*/kBookmarkBarId,
      /*server_version=*/0, /*creation_time=*/base::Time::Now(),
      syncer::UniquePosition::InitialPosition(
          syncer::UniquePosition::RandomSuffix())
          .ToProto(),
      specifics);
  specifics.mutable_bookmark()->set_legacy_canonicalized_title(
      kOtherBookmarksTag);
  bookmark_tracker->Add(
      /*bookmark_node=*/model->other_node(),
      /*sync_id=*/kOtherBookmarksId,
      /*server_version=*/0, /*creation_time=*/base::Time::Now(),
      syncer::UniquePosition::InitialPosition(
          syncer::UniquePosition::RandomSuffix())
          .ToProto(),
      specifics);
  specifics.mutable_bookmark()->set_legacy_canonicalized_title(
      kMobileBookmarksTag);
  bookmark_tracker->Add(
      /*bookmark_node=*/model->mobile_node(),
      /*sync_id=*/kMobileBookmarksId,
      /*server_version=*/0, /*creation_time=*/base::Time::Now(),
      syncer::UniquePosition::InitialPosition(
          syncer::UniquePosition::RandomSuffix())
          .ToProto(),
      specifics);
  BookmarkModelObserverImpl observer(
      nudge_for_commit_closure()->Get(),
      /*on_bookmark_model_being_deleted_closure=*/base::DoNothing(),
      bookmark_tracker.get());

  model->AddObserver(&observer);

  EXPECT_CALL(*nudge_for_commit_closure(), Run()).Times(0);
  // In the TestBookmarkClient, descendants of managed nodes shouldn't be
  // synced.
  const bookmarks::BookmarkNode* unsyncable_node =
      model->AddURL(/*parent=*/managed_node, /*index=*/0,
                    base::ASCIIToUTF16("Title"), GURL("http://www.url.com"));
  // Only permanent folders should be tracked.
  EXPECT_THAT(bookmark_tracker->TrackedEntitiesCountForTest(), 3U);

  EXPECT_CALL(*nudge_for_commit_closure(), Run()).Times(0);
  // In the TestBookmarkClient, descendants of managed nodes shouldn't be
  // synced.
  model->SetTitle(unsyncable_node, base::ASCIIToUTF16("NewTitle"));
  // Only permanent folders should be tracked.
  EXPECT_THAT(bookmark_tracker->TrackedEntitiesCountForTest(), 3U);

  EXPECT_CALL(*nudge_for_commit_closure(), Run()).Times(0);
  // In the TestBookmarkClient, descendants of managed nodes shouldn't be
  // synced.
  model->Remove(unsyncable_node);

  // Only permanent folders should be tracked.
  EXPECT_THAT(bookmark_tracker->TrackedEntitiesCountForTest(), 3U);
  model->RemoveObserver(&observer);
}

TEST_F(BookmarkModelObserverImplTest, ShouldAddChildrenInArbitraryOrder) {
  std::unique_ptr<SyncedBookmarkTracker> bookmark_tracker =
      SyncedBookmarkTracker::CreateEmpty(sync_pb::ModelTypeState());
  BookmarkModelObserverImpl observer(
      /*nudge_for_commit_closure=*/base::DoNothing(),
      /*on_bookmark_model_being_deleted_closure=*/base::DoNothing(),
      bookmark_tracker.get());
  const bookmarks::BookmarkNode* bookmark_bar_node =
      bookmark_model()->bookmark_bar_node();
  // Add the bookmark bar to the tracker.
  sync_pb::EntitySpecifics specifics;
  specifics.mutable_bookmark()->set_legacy_canonicalized_title(kBookmarkBarTag);
  bookmark_tracker->Add(
      /*bookmark_node=*/bookmark_model()->bookmark_bar_node(),
      /*sync_id=*/kBookmarkBarId,
      /*server_version=*/0, /*creation_time=*/base::Time::Now(),
      syncer::UniquePosition::InitialPosition(
          syncer::UniquePosition::RandomSuffix())
          .ToProto(),
      specifics);

  // Build this structure:
  // bookmark_bar
  //  |- folder0
  //  |- folder1
  //  |- folder2
  //  |- folder3
  //  |- folder4

  const bookmarks::BookmarkNode* nodes[5];
  for (size_t i = 0; i < 5; i++) {
    nodes[i] = bookmark_model()->AddFolder(
        /*parent=*/bookmark_bar_node, /*index=*/i,
        base::UTF8ToUTF16("folder" + std::to_string(i)));
  }

  // Now simulate calling the observer as if the nodes are added in that order.
  // 4,0,2,3,1.
  observer.BookmarkNodeAdded(bookmark_model(), bookmark_bar_node, 4);
  observer.BookmarkNodeAdded(bookmark_model(), bookmark_bar_node, 0);
  observer.BookmarkNodeAdded(bookmark_model(), bookmark_bar_node, 2);
  observer.BookmarkNodeAdded(bookmark_model(), bookmark_bar_node, 3);
  observer.BookmarkNodeAdded(bookmark_model(), bookmark_bar_node, 1);

  ASSERT_THAT(bookmark_tracker->TrackedEntitiesCountForTest(), 6U);

  // Check that position information match the children order.
  EXPECT_TRUE(PositionOf(nodes[0]).LessThan(PositionOf(nodes[1])));
  EXPECT_TRUE(PositionOf(nodes[1]).LessThan(PositionOf(nodes[2])));
  EXPECT_TRUE(PositionOf(nodes[2]).LessThan(PositionOf(nodes[3])));
  EXPECT_TRUE(PositionOf(nodes[3]).LessThan(PositionOf(nodes[4])));
}

TEST_F(BookmarkModelObserverImplTest,
       ShouldCallOnBookmarkModelBeingDeletedClosure) {
  std::unique_ptr<SyncedBookmarkTracker> bookmark_tracker =
      SyncedBookmarkTracker::CreateEmpty(sync_pb::ModelTypeState());

  NiceMock<base::MockCallback<base::OnceClosure>>
      on_bookmark_model_being_deleted_closure_mock;

  BookmarkModelObserverImpl observer(
      /*nudge_for_commit_closure=*/base::DoNothing(),
      on_bookmark_model_being_deleted_closure_mock.Get(),
      bookmark_tracker.get());

  EXPECT_CALL(on_bookmark_model_being_deleted_closure_mock, Run());
  observer.BookmarkModelBeingDeleted(/*model=*/nullptr);
}

TEST_F(BookmarkModelObserverImplTest, ShouldNotIssueCommitUponFaviconLoad) {
  const GURL kBookmarkUrl("http://www.url.com");
  const GURL kIconUrl("http://www.url.com/favicon.ico");
  const SkColor kColor = SK_ColorRED;

  const bookmarks::BookmarkNode* bookmark_bar_node =
      bookmark_model()->bookmark_bar_node();
  const bookmarks::BookmarkNode* bookmark_node = bookmark_model()->AddURL(
      /*parent=*/bookmark_bar_node, /*index=*/0, base::UTF8ToUTF16("title"),
      kBookmarkUrl);

  ASSERT_TRUE(
      bookmark_client()->SimulateFaviconLoaded(kBookmarkUrl, kIconUrl, kColor));
  SimulateCommitResponseForAllLocalChanges();
  ASSERT_THAT(bookmark_tracker()->GetEntitiesWithLocalChanges(kMaxEntries),
              IsEmpty());

  const SyncedBookmarkTracker::Entity* entity =
      bookmark_tracker()->GetEntityForBookmarkNode(bookmark_node);
  ASSERT_THAT(entity, NotNull());
  ASSERT_TRUE(entity->metadata()->has_bookmark_favicon_hash());
  const uint32_t initial_favicon_hash =
      entity->metadata()->bookmark_favicon_hash();

  // Clear the specifics hash (as if the proto definition would have changed).
  // This is needed because otherwise the commit is trivially optimized away
  // (i.e. literally nothing changed).
  bookmark_tracker()->ClearSpecificsHashForTest(entity);

  // Mimic the very same favicon being loaded again (similar to a startup
  // scenario). Note that OnFaviconsChanged() needs no icon URL to invalidate
  // the favicon of a bookmark.
  EXPECT_CALL(*nudge_for_commit_closure(), Run()).Times(0);
  bookmark_model()->OnFaviconsChanged(/*page_urls=*/{kBookmarkUrl},
                                      /*icon_url=*/GURL());
  ASSERT_TRUE(bookmark_node->is_favicon_loading());
  ASSERT_TRUE(
      bookmark_client()->SimulateFaviconLoaded(kBookmarkUrl, kIconUrl, kColor));

  EXPECT_TRUE(entity->metadata()->has_bookmark_favicon_hash());
  EXPECT_THAT(entity->metadata()->bookmark_favicon_hash(),
              Eq(initial_favicon_hash));
  EXPECT_THAT(bookmark_tracker()->GetEntitiesWithLocalChanges(kMaxEntries),
              IsEmpty());
}

TEST_F(BookmarkModelObserverImplTest, ShouldCommitLocalFaviconChange) {
  const GURL kBookmarkUrl("http://www.url.com");
  const GURL kInitialIconUrl("http://www.url.com/initial.ico");
  const GURL kFinalIconUrl("http://www.url.com/final.ico");

  const bookmarks::BookmarkNode* bookmark_bar_node =
      bookmark_model()->bookmark_bar_node();
  const bookmarks::BookmarkNode* bookmark_node = bookmark_model()->AddURL(
      /*parent=*/bookmark_bar_node, /*index=*/0, base::UTF8ToUTF16("title"),
      kBookmarkUrl);

  ASSERT_TRUE(bookmark_node->is_favicon_loading());
  ASSERT_TRUE(bookmark_client()->SimulateFaviconLoaded(
      kBookmarkUrl, kInitialIconUrl, SK_ColorRED));
  SimulateCommitResponseForAllLocalChanges();
  ASSERT_THAT(bookmark_tracker()->GetEntitiesWithLocalChanges(kMaxEntries),
              IsEmpty());

  const SyncedBookmarkTracker::Entity* entity =
      bookmark_tracker()->GetEntityForBookmarkNode(bookmark_node);
  ASSERT_THAT(entity, NotNull());
  ASSERT_TRUE(entity->metadata()->has_bookmark_favicon_hash());
  const uint32_t initial_favicon_hash =
      entity->metadata()->bookmark_favicon_hash();

  // A favicon change should trigger a commit nudge once the favicon loads, but
  // not earlier. Note that OnFaviconsChanged() needs no icon URL to invalidate
  // the favicon of a bookmark.
  EXPECT_CALL(*nudge_for_commit_closure(), Run()).Times(0);
  bookmark_model()->OnFaviconsChanged(/*page_urls=*/{kBookmarkUrl},
                                      /*icon_url=*/GURL());
  ASSERT_TRUE(bookmark_node->is_favicon_loading());

  EXPECT_CALL(*nudge_for_commit_closure(), Run());
  ASSERT_TRUE(bookmark_client()->SimulateFaviconLoaded(
      kBookmarkUrl, kFinalIconUrl, SK_ColorBLUE));

  EXPECT_TRUE(entity->metadata()->has_bookmark_favicon_hash());
  EXPECT_THAT(entity->metadata()->bookmark_favicon_hash(),
              Ne(initial_favicon_hash));
  EXPECT_THAT(bookmark_tracker()->GetEntitiesWithLocalChanges(kMaxEntries),
              ElementsAre(HasBookmarkNode(bookmark_node)));
}

TEST_F(BookmarkModelObserverImplTest,
       ShouldNudgeForCommitOnFaviconLoadAfterRestart) {
  base::test::ScopedFeatureList feature_list;
  feature_list.InitAndEnableFeature(
      switches::kSyncDoNotCommitBookmarksWithoutFavicon);

  const GURL kBookmarkUrl("http://www.url.com");
  const GURL kIconUrl("http://www.url.com/favicon.ico");
  const SkColor kColor = SK_ColorRED;

  // Simulate work after restart. Add a new bookmark to a model and its
  // specifics to the tracker without loading favicon.
  bookmark_model()->RemoveObserver(observer());

  // Add a new node with specifics and mark it unsynced.
  const bookmarks::BookmarkNode* bookmark_bar_node =
      bookmark_model()->bookmark_bar_node();
  const bookmarks::BookmarkNode* bookmark_node = bookmark_model()->AddURL(
      /*parent=*/bookmark_bar_node, /*index=*/0, base::UTF8ToUTF16("title"),
      kBookmarkUrl);

  sync_pb::EntitySpecifics specifics =
      CreateSpecificsFromBookmarkNode(bookmark_node, bookmark_model(),
                                      /*force_favicon_load=*/false,
                                      /*include_guid=*/true);
  const gfx::Image favicon_image = CreateTestImage(kColor);
  scoped_refptr<base::RefCountedMemory> favicon_bytes =
      favicon_image.As1xPNGBytes();
  specifics.mutable_bookmark()->set_favicon(favicon_bytes->front(),
                                            favicon_bytes->size());
  specifics.mutable_bookmark()->set_icon_url(kIconUrl.spec());

  const SyncedBookmarkTracker::Entity* entity = bookmark_tracker()->Add(
      bookmark_node, "id", /*server_version=*/1, base::Time::Now(),
      syncer::UniquePosition::InitialPosition(
          syncer::UniquePosition::RandomSuffix())
          .ToProto(),
      specifics);
  bookmark_tracker()->IncrementSequenceNumber(entity);

  // Restore state.
  bookmark_model()->AddObserver(observer());

  // Currently there is the unsynced |entity| which has no loaded favicon.
  ASSERT_FALSE(bookmark_node->is_favicon_loaded());
  ASSERT_TRUE(entity->IsUnsynced());

  EXPECT_CALL(*nudge_for_commit_closure(), Run());
  bookmark_model()->GetFavicon(bookmark_node);
  ASSERT_TRUE(bookmark_client()->SimulateFaviconLoaded(kBookmarkUrl, kIconUrl,
                                                       SK_ColorRED));
}

TEST_F(BookmarkModelObserverImplTest,
       ShouldAddRestoredBookmarkWhenTombstoneCommitMayHaveStarted) {
  const bookmarks::BookmarkNode* bookmark_bar_node =
      bookmark_model()->bookmark_bar_node();
  const bookmarks::BookmarkNode* folder = bookmark_model()->AddFolder(
      bookmark_bar_node, 0, base::UTF8ToUTF16("Title"));
  // Check that the bookmark was added by observer.
  const SyncedBookmarkTracker::Entity* folder_entity =
      bookmark_tracker()->GetEntityForBookmarkNode(folder);
  ASSERT_THAT(folder_entity, NotNull());
  ASSERT_TRUE(folder_entity->IsUnsynced());
  SimulateCommitResponseForAllLocalChanges();
  ASSERT_FALSE(folder_entity->IsUnsynced());

  // Now delete the entity and restore it with the same bookmark node.
  BookmarkUndoService undo_service;
  undo_service.Start(bookmark_model());
  bookmark_model()->Remove(folder);

  // The removed bookmark must be saved in the undo service.
  ASSERT_EQ(undo_service.undo_manager()->undo_count(), 1u);
  ASSERT_THAT(bookmark_tracker()->GetEntityForBookmarkNode(folder), IsNull());

  // Check that the entity is a tombstone now.
  const std::vector<const SyncedBookmarkTracker::Entity*> local_changes =
      bookmark_tracker()->GetEntitiesWithLocalChanges(/*max_entries=*/2);
  ASSERT_EQ(local_changes.size(), 1u);
  ASSERT_EQ(local_changes.front(), folder_entity);
  ASSERT_TRUE(local_changes.front()->metadata()->is_deleted());
  ASSERT_EQ(bookmark_tracker()->GetTombstoneEntityForGuid(folder->guid()),
            folder_entity);

  // Restore the removed bookmark.
  undo_service.undo_manager()->Undo();
  undo_service.Shutdown();

  EXPECT_EQ(folder_entity,
            bookmark_tracker()->GetEntityForBookmarkNode(folder));
  EXPECT_TRUE(folder_entity->IsUnsynced());
  EXPECT_FALSE(folder_entity->metadata()->is_deleted());
  EXPECT_THAT(bookmark_tracker()->GetTombstoneEntityForGuid(folder->guid()),
              IsNull());
  EXPECT_EQ(folder_entity->bookmark_node(), folder);
}

// Tests that the bookmark entity will be committed if its favicon is deleted.
TEST_F(BookmarkModelObserverImplTest, ShouldCommitOnDeleteFavicon) {
  const GURL kBookmarkUrl("http://www.url.com");
  const GURL kIconUrl("http://www.url.com/favicon.ico");

  // Add a new node with specifics.
  const bookmarks::BookmarkNode* bookmark_bar_node =
      bookmark_model()->bookmark_bar_node();
  const bookmarks::BookmarkNode* bookmark_node = bookmark_model()->AddURL(
      /*parent=*/bookmark_bar_node, /*index=*/0, base::UTF8ToUTF16("title"),
      kBookmarkUrl);

  ASSERT_TRUE(bookmark_node->is_favicon_loading());
  ASSERT_TRUE(bookmark_client()->SimulateFaviconLoaded(kBookmarkUrl, kIconUrl,
                                                       SK_ColorRED));

  const SyncedBookmarkTracker::Entity* entity =
      bookmark_tracker()->GetEntityForBookmarkNode(bookmark_node);
  ASSERT_THAT(entity, NotNull());
  ASSERT_TRUE(entity->IsUnsynced());

  SimulateCommitResponseForAllLocalChanges();

  ASSERT_FALSE(bookmark_tracker()->HasLocalChanges());

  // Delete favicon and check that its deletion is committed.
  bookmark_model()->OnFaviconsChanged({kBookmarkUrl}, GURL());
  ASSERT_TRUE(bookmark_node->is_favicon_loading());
  ASSERT_TRUE(bookmark_client()->SimulateEmptyFaviconLoaded(kBookmarkUrl));

  EXPECT_TRUE(entity->IsUnsynced());
}

}  // namespace

}  // namespace sync_bookmarks
