// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/previews/core/previews_block_list.h"

#include <algorithm>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/field_trial.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/simple_test_clock.h"
#include "base/test/task_environment.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/time.h"
#include "components/blocklist/opt_out_blocklist/opt_out_blocklist_delegate.h"
#include "components/blocklist/opt_out_blocklist/opt_out_blocklist_item.h"
#include "components/blocklist/opt_out_blocklist/opt_out_store.h"
#include "components/previews/core/previews_experiments.h"
#include "components/variations/variations_associated_data.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace previews {

namespace {

// Mock class to test that PreviewsBlockList notifies the delegate with correct
// events (e.g. New host blocklisted, user blocklisted, and blocklist cleared).
class TestOptOutBlocklistDelegate : public blocklist::OptOutBlocklistDelegate {
 public:
  TestOptOutBlocklistDelegate() = default;

  // blocklist::OptOutBlocklistDelegate:
  void OnNewBlocklistedHost(const std::string& host, base::Time time) override {
  }
  void OnUserBlocklistedStatusChange(bool blocklisted) override {}
  void OnBlocklistCleared(base::Time time) override {}
};

class TestPreviewsBlockList : public PreviewsBlockList {
 public:
  TestPreviewsBlockList(
      std::unique_ptr<blocklist::OptOutStore> opt_out_store,
      base::Clock* clock,
      blocklist::OptOutBlocklistDelegate* blocklist_delegate,
      blocklist::BlocklistData::AllowedTypesAndVersions allowed_types)
      : PreviewsBlockList(std::move(opt_out_store),
                          clock,
                          blocklist_delegate,
                          allowed_types) {}
  ~TestPreviewsBlockList() override = default;

  bool ShouldUseSessionPolicy(base::TimeDelta* duration,
                              size_t* history,
                              int* threshold) const override {
    return PreviewsBlockList::ShouldUseSessionPolicy(duration, history,
                                                     threshold);
  }
  bool ShouldUsePersistentPolicy(base::TimeDelta* duration,
                                 size_t* history,
                                 int* threshold) const override {
    return PreviewsBlockList::ShouldUsePersistentPolicy(duration, history,
                                                        threshold);
  }
  bool ShouldUseHostPolicy(base::TimeDelta* duration,
                           size_t* history,
                           int* threshold,
                           size_t* max_hosts) const override {
    return PreviewsBlockList::ShouldUseHostPolicy(duration, history, threshold,
                                                  max_hosts);
  }
  bool ShouldUseTypePolicy(base::TimeDelta* duration,
                           size_t* history,
                           int* threshold) const override {
    return PreviewsBlockList::ShouldUseTypePolicy(duration, history, threshold);
  }
};

class PreviewsBlockListTest : public testing::Test {
 public:
  PreviewsBlockListTest() : passed_reasons_({}) {}
  ~PreviewsBlockListTest() override = default;

  void TearDown() override { variations::testing::ClearAllVariationParams(); }

  void StartTest() {
    if (params_.size() > 0) {
      ASSERT_TRUE(variations::AssociateVariationParams("ClientSidePreviews",
                                                       "Enabled", params_));
      ASSERT_TRUE(base::FieldTrialList::CreateFieldTrial("ClientSidePreviews",
                                                         "Enabled"));
      params_.clear();
    }

    blocklist::BlocklistData::AllowedTypesAndVersions allowed_types;
    allowed_types[static_cast<int>(PreviewsType::DEFER_ALL_SCRIPT)] = 0;
    block_list_ = std::make_unique<TestPreviewsBlockList>(
        nullptr, &test_clock_, &blocklist_delegate_, std::move(allowed_types));

    passed_reasons_ = {};
  }

  void SetHostHistoryParam(size_t host_history) {
    params_["per_host_max_stored_history_length"] =
        base::NumberToString(host_history);
  }

  void SetHostIndifferentHistoryParam(size_t host_indifferent_history) {
    params_["host_indifferent_max_stored_history_length"] =
        base::NumberToString(host_indifferent_history);
  }

  void SetHostThresholdParam(int per_host_threshold) {
    params_["per_host_opt_out_threshold"] =
        base::NumberToString(per_host_threshold);
  }

  void SetHostIndifferentThresholdParam(int host_indifferent_threshold) {
    params_["host_indifferent_opt_out_threshold"] =
        base::NumberToString(host_indifferent_threshold);
  }

  void SetHostDurationParam(int duration_in_days) {
    // TODO(crbug.com/1092102): Migrate to per_host_black_list_duration_in_days
    params_["per_host_black_list_duration_in_days"] =
        base::NumberToString(duration_in_days);
  }

  void SetHostIndifferentDurationParam(int duration_in_days) {
    // TODO(crbug.com/1092102): Migrate to
    // host_indifferent_block_list_duration_in_days
    params_["host_indifferent_black_list_duration_in_days"] =
        base::NumberToString(duration_in_days);
  }

  void SetSingleOptOutDurationParam(int single_opt_out_duration) {
    params_["single_opt_out_duration_in_seconds"] =
        base::NumberToString(single_opt_out_duration);
  }

  void SetMaxHostInBlockListParam(size_t max_hosts_in_blocklist) {
    // TODO(crbug.com/1092102): Migrate to max_hosts_in_blocklist
    params_["max_hosts_in_blacklist"] =
        base::NumberToString(max_hosts_in_blocklist);
  }

 protected:
  base::test::SingleThreadTaskEnvironment task_environment_;

  // Observer to |block_list_|.
  TestOptOutBlocklistDelegate blocklist_delegate_;

  base::SimpleTestClock test_clock_;
  std::map<std::string, std::string> params_;

  std::unique_ptr<TestPreviewsBlockList> block_list_;
  std::vector<PreviewsEligibilityReason> passed_reasons_;

 private:
  DISALLOW_COPY_AND_ASSIGN(PreviewsBlockListTest);
};

TEST_F(PreviewsBlockListTest, AddPreviewUMA) {
  base::HistogramTester histogram_tester;
  const GURL url("http://www.url.com");

  StartTest();

  block_list_->AddPreviewNavigation(url, false, PreviewsType::DEFER_ALL_SCRIPT);
  histogram_tester.ExpectUniqueSample(
      "Previews.OptOut.UserOptedOut.DeferAllScript", 0, 1);
  histogram_tester.ExpectUniqueSample("Previews.OptOut.UserOptedOut", 0, 1);
  block_list_->AddPreviewNavigation(url, true, PreviewsType::DEFER_ALL_SCRIPT);
  histogram_tester.ExpectBucketCount(
      "Previews.OptOut.UserOptedOut.DeferAllScript", 1, 1);
  histogram_tester.ExpectBucketCount("Previews.OptOut.UserOptedOut", 1, 1);
}

TEST_F(PreviewsBlockListTest, SessionParams) {
  int duration_seconds = 5;
  SetSingleOptOutDurationParam(duration_seconds);

  StartTest();

  base::TimeDelta duration;
  size_t history = 0;
  int threshold = 0;

  EXPECT_TRUE(
      block_list_->ShouldUseSessionPolicy(&duration, &history, &threshold));
  EXPECT_EQ(base::TimeDelta::FromSeconds(duration_seconds), duration);
  EXPECT_EQ(1u, history);
  EXPECT_EQ(1, threshold);
}

TEST_F(PreviewsBlockListTest, PersistentParams) {
  int duration_days = 5;
  size_t expected_history = 6;
  int expected_threshold = 4;
  SetHostIndifferentThresholdParam(expected_threshold);
  SetHostIndifferentHistoryParam(expected_history);
  SetHostIndifferentDurationParam(duration_days);

  StartTest();

  base::TimeDelta duration;
  size_t history = 0;
  int threshold = 0;

  EXPECT_TRUE(
      block_list_->ShouldUsePersistentPolicy(&duration, &history, &threshold));
  EXPECT_EQ(base::TimeDelta::FromDays(duration_days), duration);
  EXPECT_EQ(expected_history, history);
  EXPECT_EQ(expected_threshold, threshold);
}

TEST_F(PreviewsBlockListTest, HostParams) {
  int duration_days = 5;
  size_t expected_history = 6;
  int expected_threshold = 4;
  size_t expected_max_hosts = 11;
  SetHostThresholdParam(expected_threshold);
  SetHostHistoryParam(expected_history);
  SetHostDurationParam(duration_days);
  SetMaxHostInBlockListParam(expected_max_hosts);

  StartTest();

  base::TimeDelta duration;
  size_t history = 0;
  int threshold = 0;
  size_t max_hosts = 0;

  EXPECT_TRUE(block_list_->ShouldUseHostPolicy(&duration, &history, &threshold,
                                               &max_hosts));
  EXPECT_EQ(base::TimeDelta::FromDays(duration_days), duration);
  EXPECT_EQ(expected_history, history);
  EXPECT_EQ(expected_threshold, threshold);
  EXPECT_EQ(expected_max_hosts, max_hosts);
}

TEST_F(PreviewsBlockListTest, TypeParams) {
  StartTest();
  EXPECT_FALSE(block_list_->ShouldUseTypePolicy(nullptr, nullptr, nullptr));
}

}  // namespace

}  // namespace previews
