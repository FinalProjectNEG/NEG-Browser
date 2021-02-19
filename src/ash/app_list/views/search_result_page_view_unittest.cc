// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ash/app_list/views/search_result_page_view.h"

#include <memory>
#include <utility>
#include <vector>

#include "ash/app_list/model/app_list_model.h"
#include "ash/app_list/test/app_list_test_view_delegate.h"
#include "ash/app_list/test/test_search_result.h"
#include "ash/app_list/views/app_list_main_view.h"
#include "ash/app_list/views/app_list_view.h"
#include "ash/app_list/views/contents_view.h"
#include "ash/app_list/views/search_result_list_view.h"
#include "ash/app_list/views/search_result_tile_item_list_view.h"
#include "ash/app_list/views/search_result_view.h"
#include "ash/public/cpp/app_list/app_list_features.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/test/scoped_feature_list.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "ui/aura/window.h"
#include "ui/views/test/views_test_base.h"

namespace ash {
namespace test {

class SearchResultPageViewTest : public views::ViewsTestBase {
 public:
  SearchResultPageViewTest() = default;
  ~SearchResultPageViewTest() override = default;

  // Overridden from testing::Test:
  void SetUp() override {
    views::ViewsTestBase::SetUp();

    // Setting up the feature set.
    // Zero State will affect the UI behavior significantly. This test works
    // if zero state feature is disabled.
    // TODO(crbug.com/925195): Add different test suites for zero state.
    scoped_feature_list_.InitWithFeatures(
        {}, {app_list_features::kEnableZeroStateSuggestions});

    ASSERT_FALSE(app_list_features::IsZeroStateSuggestionsEnabled());

    // Setting up views.
    delegate_ = std::make_unique<AppListTestViewDelegate>();
    app_list_view_ = new AppListView(delegate_.get());
    app_list_view_->InitView(GetContext());
    app_list_view_->Show(false /*is_side_shelf*/);

    ContentsView* contents_view =
        app_list_view_->app_list_main_view()->contents_view();
    view_ = contents_view->search_results_page_view();
    tile_list_view_ =
        contents_view->search_result_tile_item_list_view_for_test();
    list_view_ = contents_view->search_result_list_view_for_test();
  }
  void TearDown() override {
    app_list_view_->GetWidget()->Close();
    views::ViewsTestBase::TearDown();
  }

 protected:
  SearchResultPageView* view() const { return view_; }

  SearchResultTileItemListView* tile_list_view() const {
    return tile_list_view_;
  }
  SearchResultListView* list_view() const { return list_view_; }

  SearchModel::SearchResults* GetResults() const {
    return delegate_->GetSearchModel()->results();
  }

 private:
  AppListView* app_list_view_ = nullptr;  // Owned by native widget.
  SearchResultPageView* view_ = nullptr;  // Owned by views hierarchy.
  SearchResultTileItemListView* tile_list_view_ =
      nullptr;                                 // Owned by views hierarchy.
  SearchResultListView* list_view_ = nullptr;  // Owned by views hierarchy.
  std::unique_ptr<AppListTestViewDelegate> delegate_;
  base::test::ScopedFeatureList scoped_feature_list_;

  DISALLOW_COPY_AND_ASSIGN(SearchResultPageViewTest);
};

TEST_F(SearchResultPageViewTest, ResultsSorted) {
  SearchModel::SearchResults* results = GetResults();

  // Add 3 results and expect the tile list view to be the first result
  // container view.
  TestSearchResult* tile_result = new TestSearchResult();
  tile_result->set_display_type(ash::SearchResultDisplayType::kTile);
  tile_result->set_display_score(1.0);
  results->Add(base::WrapUnique(tile_result));
  {
    TestSearchResult* list_result = new TestSearchResult();
    list_result->set_display_type(ash::SearchResultDisplayType::kList);
    list_result->set_display_score(0.5);
    results->Add(base::WrapUnique(list_result));
  }
  {
    TestSearchResult* list_result = new TestSearchResult();
    list_result->set_display_type(ash::SearchResultDisplayType::kList);
    list_result->set_display_score(0.3);
    results->Add(base::WrapUnique(list_result));
  }

  // Adding results will schedule Update().
  RunPendingMessages();

  EXPECT_EQ(tile_list_view(), view()->result_container_views()[0]);
  EXPECT_EQ(list_view(), view()->result_container_views()[1]);

  // Change the relevance of the tile result to be lower than list results. The
  // tile container should still be displayed first.
  tile_result->set_display_score(0.4);

  results->NotifyItemsChanged(0, 1);
  RunPendingMessages();

  EXPECT_EQ(tile_list_view(), view()->result_container_views()[0]);
  EXPECT_EQ(list_view(), view()->result_container_views()[1]);
}

TEST_F(SearchResultPageViewTest, TileResultsSortedBeforeEmptyListResults) {
  SearchModel::SearchResults* results = GetResults();

  // Add a tile result with 0 score and leave the list results empty - list
  // result container should be sorted after tile results.
  auto tile_result = std::make_unique<TestSearchResult>();
  tile_result->set_display_type(ash::SearchResultDisplayType::kTile);
  tile_result->set_display_score(0.0);
  results->Add(std::move(tile_result));

  // Adding results will schedule Update().
  RunPendingMessages();

  EXPECT_EQ(tile_list_view(), view()->result_container_views()[0]);
}

TEST_F(SearchResultPageViewTest, ListResultsSortedBeforeEmptyTileResults) {
  SearchModel::SearchResults* results = GetResults();

  // Add a list result with 0 score and leave the tile results empty - list
  // result container should be sorted before tile results.
  auto list_result = std::make_unique<TestSearchResult>();
  list_result->set_display_type(ash::SearchResultDisplayType::kList);
  list_result->set_display_score(0.0);
  results->Add(std::move(list_result));

  // Adding results will schedule Update().
  RunPendingMessages();

  EXPECT_EQ(list_view(), view()->result_container_views()[0]);
}

}  // namespace test
}  // namespace ash
