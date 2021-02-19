// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/performance_manager/v8_memory/v8_context_tracker_internal.h"

#include <memory>

#include "base/optional.h"
#include "base/test/gtest_util.h"
#include "components/performance_manager/execution_context/execution_context_registry_impl.h"
#include "components/performance_manager/test_support/graph_test_harness.h"
#include "components/performance_manager/test_support/mock_graphs.h"
#include "components/performance_manager/v8_memory/v8_context_tracker.h"
#include "components/performance_manager/v8_memory/v8_context_tracker_types.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/tokens/tokens.h"

namespace performance_manager {
namespace v8_memory {
namespace internal {

namespace {

class V8ContextTrackerInternalTest : public GraphTestHarness {
 public:
  V8ContextTrackerInternalTest()
      : registry_(graph()->PassToGraph(
            std::make_unique<
                execution_context::ExecutionContextRegistryImpl>())),
        tracker_(graph()->PassToGraph(std::make_unique<V8ContextTracker>())),
        mock_graph_(graph()) {}

  ~V8ContextTrackerInternalTest() override = default;

  V8ContextTrackerDataStore* data_store() const {
    return tracker_->data_store();
  }

  execution_context::ExecutionContextRegistry* const registry_ = nullptr;
  V8ContextTracker* const tracker_ = nullptr;
  MockSinglePageWithMultipleProcessesGraph mock_graph_;
};

using V8ContextTrackerInternalDeathTest = V8ContextTrackerInternalTest;

}  // namespace

TEST_F(V8ContextTrackerInternalDeathTest,
       PassingUnreferencedExecutionContextDataFails) {
  auto* process_data = ProcessData::GetOrCreate(
      static_cast<ProcessNodeImpl*>(mock_graph_.process.get()));
  std::unique_ptr<ExecutionContextData> ec_data =
      std::make_unique<ExecutionContextData>(
          process_data, mock_graph_.frame->frame_token(), base::nullopt);
  EXPECT_TRUE(ec_data->ShouldDestroy());
  EXPECT_DCHECK_DEATH(data_store()->Pass(std::move(ec_data)));
}

TEST_F(V8ContextTrackerInternalDeathTest, SameProcessRemoteFrameDataExplodes) {
  auto* process_data = ProcessData::GetOrCreate(
      static_cast<ProcessNodeImpl*>(mock_graph_.process.get()));
  std::unique_ptr<ExecutionContextData> ec_data =
      std::make_unique<ExecutionContextData>(
          process_data, mock_graph_.frame->frame_token(), base::nullopt);
  std::unique_ptr<RemoteFrameData> rf_data;
  EXPECT_DCHECK_DEATH(
      rf_data = std::make_unique<RemoteFrameData>(
          process_data, blink::RemoteFrameToken(), ec_data.get()));
}

TEST_F(V8ContextTrackerInternalDeathTest, CrossProcessV8ContextDataExplodes) {
  auto* process_data = ProcessData::GetOrCreate(
      static_cast<ProcessNodeImpl*>(mock_graph_.process.get()));
  auto* other_process_data = ProcessData::GetOrCreate(
      static_cast<ProcessNodeImpl*>(mock_graph_.other_process.get()));
  std::unique_ptr<ExecutionContextData> ec_data =
      std::make_unique<ExecutionContextData>(
          process_data, mock_graph_.frame->frame_token(), base::nullopt);
  std::unique_ptr<V8ContextData> v8_data;
  EXPECT_DCHECK_DEATH(
      v8_data = std::make_unique<V8ContextData>(
          other_process_data, V8ContextDescription(), ec_data.get()));
}

TEST_F(V8ContextTrackerInternalTest, ExecutionContextDataShouldDestroy) {
  auto* process_data = ProcessData::GetOrCreate(
      static_cast<ProcessNodeImpl*>(mock_graph_.process.get()));

  // With no references "ShouldDestroy" should return true.
  std::unique_ptr<ExecutionContextData> ec_data =
      std::make_unique<ExecutionContextData>(
          process_data, mock_graph_.frame->frame_token(), base::nullopt);
  EXPECT_FALSE(ec_data->remote_frame_data());
  EXPECT_EQ(0u, ec_data->v8_context_count());
  EXPECT_TRUE(ec_data->ShouldDestroy());

  // Adding a RemoteFrameData reference should mark "ShouldDestroy" as false.
  auto* other_process_data = ProcessData::GetOrCreate(
      static_cast<ProcessNodeImpl*>(mock_graph_.other_process.get()));
  std::unique_ptr<RemoteFrameData> rf_data = std::make_unique<RemoteFrameData>(
      other_process_data, blink::RemoteFrameToken(), ec_data.get());
  EXPECT_TRUE(ec_data->remote_frame_data());
  EXPECT_EQ(0u, ec_data->v8_context_count());
  EXPECT_FALSE(ec_data->ShouldDestroy());

  // Adding a V8ContextData should also keep the object alive.
  std::unique_ptr<V8ContextData> v8_data1 = std::make_unique<V8ContextData>(
      process_data, V8ContextDescription(), ec_data.get());
  EXPECT_TRUE(ec_data->remote_frame_data());
  EXPECT_EQ(1u, ec_data->v8_context_count());
  EXPECT_FALSE(ec_data->ShouldDestroy());

  // Add another V8ContextData.
  std::unique_ptr<V8ContextData> v8_data2 = std::make_unique<V8ContextData>(
      process_data, V8ContextDescription(), ec_data.get());
  EXPECT_TRUE(ec_data->remote_frame_data());
  EXPECT_EQ(2u, ec_data->v8_context_count());
  EXPECT_FALSE(ec_data->ShouldDestroy());

  // Destroy one of the V8ContextDatas.
  v8_data1.reset();
  EXPECT_TRUE(ec_data->remote_frame_data());
  EXPECT_EQ(1u, ec_data->v8_context_count());
  EXPECT_FALSE(ec_data->ShouldDestroy());

  // Destroy the RemoteFrameData.
  rf_data.reset();
  EXPECT_FALSE(ec_data->remote_frame_data());
  EXPECT_EQ(1u, ec_data->v8_context_count());
  EXPECT_FALSE(ec_data->ShouldDestroy());

  // Destroy the last V8COntextData.
  v8_data2.reset();
  EXPECT_FALSE(ec_data->remote_frame_data());
  EXPECT_EQ(0u, ec_data->v8_context_count());
  EXPECT_TRUE(ec_data->ShouldDestroy());
}

TEST_F(V8ContextTrackerInternalTest,
       ExecutionContextDataTornDownByRemoteFrameData) {
  auto* process_data = ProcessData::GetOrCreate(
      static_cast<ProcessNodeImpl*>(mock_graph_.process.get()));

  // Create an ExecutionContextData.
  std::unique_ptr<ExecutionContextData> ec_data =
      std::make_unique<ExecutionContextData>(
          process_data, mock_graph_.frame->frame_token(), base::nullopt);
  auto* raw_ec_data = ec_data.get();
  EXPECT_FALSE(ec_data->IsTracked());

  // Create a RemoteFrameData.
  auto* other_process_data = ProcessData::GetOrCreate(
      static_cast<ProcessNodeImpl*>(mock_graph_.other_process.get()));
  std::unique_ptr<RemoteFrameData> rf_data = std::make_unique<RemoteFrameData>(
      other_process_data, blink::RemoteFrameToken(), ec_data.get());
  auto* raw_rf_data = rf_data.get();
  EXPECT_FALSE(rf_data->IsTracked());

  // Pass both of these to the Impl.
  data_store()->Pass(std::move(ec_data));
  data_store()->Pass(std::move(rf_data));
  EXPECT_TRUE(raw_ec_data->IsTracked());
  EXPECT_TRUE(raw_rf_data->IsTracked());
  EXPECT_EQ(1u, data_store()->GetExecutionContextDataCount());
  EXPECT_EQ(1u, data_store()->GetRemoteFrameDataCount());

  // Ensure that lookup works.
  auto ec_token = raw_ec_data->GetToken();
  auto rf_token = raw_rf_data->GetToken();
  EXPECT_EQ(raw_ec_data, data_store()->Get(ec_token));
  EXPECT_EQ(raw_rf_data, data_store()->Get(rf_token));

  // Delete the RemoteFrameData, and also expect the ExecutionContextData to
  // have been cleaned up.
  data_store()->Destroy(rf_token);
  EXPECT_EQ(nullptr, data_store()->Get(ec_token));
  EXPECT_EQ(nullptr, data_store()->Get(rf_token));
  EXPECT_EQ(0u, data_store()->GetExecutionContextDataCount());
  EXPECT_EQ(0u, data_store()->GetRemoteFrameDataCount());
}

TEST_F(V8ContextTrackerInternalTest,
       ExecutionContextDataTornDownByV8ContextData) {
  auto* process_data = ProcessData::GetOrCreate(
      static_cast<ProcessNodeImpl*>(mock_graph_.process.get()));

  // Create an ExecutionContextData.
  std::unique_ptr<ExecutionContextData> ec_data =
      std::make_unique<ExecutionContextData>(
          process_data, mock_graph_.frame->frame_token(), base::nullopt);
  auto* raw_ec_data = ec_data.get();
  EXPECT_FALSE(ec_data->IsTracked());

  // Create a V8ContextData.
  std::unique_ptr<V8ContextData> v8_data = std::make_unique<V8ContextData>(
      process_data, V8ContextDescription(), ec_data.get());
  auto* raw_v8_data = v8_data.get();
  EXPECT_FALSE(v8_data->IsTracked());

  // Pass both of these to the Impl.
  data_store()->Pass(std::move(ec_data));
  data_store()->Pass(std::move(v8_data));
  EXPECT_TRUE(raw_ec_data->IsTracked());
  EXPECT_TRUE(raw_v8_data->IsTracked());
  EXPECT_EQ(1u, data_store()->GetExecutionContextDataCount());
  EXPECT_EQ(1u, data_store()->GetV8ContextDataCount());

  // Ensure that lookup works.
  auto ec_token = raw_ec_data->GetToken();
  auto v8_token = raw_v8_data->GetToken();
  EXPECT_EQ(raw_ec_data, data_store()->Get(ec_token));
  EXPECT_EQ(raw_v8_data, data_store()->Get(v8_token));

  // Delete the V8ContextData, and also expect the ExecutionContextData to
  // have been cleaned up.
  data_store()->Destroy(v8_token);
  EXPECT_EQ(nullptr, data_store()->Get(ec_token));
  EXPECT_EQ(nullptr, data_store()->Get(v8_token));
  EXPECT_EQ(0u, data_store()->GetExecutionContextDataCount());
  EXPECT_EQ(0u, data_store()->GetV8ContextDataCount());
}

namespace {

class V8ContextTrackerInternalTearDownOrderTest
    : public V8ContextTrackerInternalTest {
 public:
  using Super = V8ContextTrackerInternalTest;

  void SetUp() override {
    Super::SetUp();

    process_data_ = ProcessData::GetOrCreate(
        static_cast<ProcessNodeImpl*>(mock_graph_.process.get()));
    other_process_data_ = ProcessData::GetOrCreate(
        static_cast<ProcessNodeImpl*>(mock_graph_.other_process.get()));

    EXPECT_EQ(0u, data_store()->GetExecutionContextDataCount());
    EXPECT_EQ(0u, data_store()->GetRemoteFrameDataCount());
    EXPECT_EQ(0u, data_store()->GetV8ContextDataCount());

    // Create an ExecutionContextData.
    std::unique_ptr<ExecutionContextData> ec_data =
        std::make_unique<ExecutionContextData>(
            process_data_, mock_graph_.frame->frame_token(), base::nullopt);
    ec_data_ = ec_data.get();

    // Create a RemoteFrameData.
    std::unique_ptr<RemoteFrameData> rf_data =
        std::make_unique<RemoteFrameData>(other_process_data_,
                                          blink::RemoteFrameToken(), ec_data_);

    // Pass these to the tracker_.
    data_store()->Pass(std::move(ec_data));
    data_store()->Pass(std::move(rf_data));

    // Create a couple V8ContextDatas.
    std::unique_ptr<V8ContextData> v8_data = std::make_unique<V8ContextData>(
        process_data_, V8ContextDescription(), ec_data_);
    data_store()->Pass(std::move(v8_data));
    v8_data = std::make_unique<V8ContextData>(process_data_,
                                              V8ContextDescription(), ec_data_);
    data_store()->Pass(std::move(v8_data));

    EXPECT_EQ(1u, data_store()->GetExecutionContextDataCount());
    EXPECT_EQ(1u, data_store()->GetRemoteFrameDataCount());
    EXPECT_EQ(2u, data_store()->GetV8ContextDataCount());
  }

  ProcessData* process_data_ = nullptr;
  ProcessData* other_process_data_ = nullptr;
  ExecutionContextData* ec_data_ = nullptr;
};

}  // namespace

TEST_F(V8ContextTrackerInternalTearDownOrderTest, RemoteBeforeLocal) {
  // Tear down the |other_process| which has "RemoteFrame" entries.
  other_process_data_->TearDown();
  EXPECT_EQ(1u, data_store()->GetExecutionContextDataCount());
  EXPECT_EQ(0u, data_store()->GetRemoteFrameDataCount());
  EXPECT_EQ(2u, data_store()->GetV8ContextDataCount());
  EXPECT_FALSE(ec_data_->remote_frame_data());

  // Now tear down the main |process|.
  process_data_->TearDown();
  EXPECT_EQ(0u, data_store()->GetExecutionContextDataCount());
  EXPECT_EQ(0u, data_store()->GetRemoteFrameDataCount());
  EXPECT_EQ(0u, data_store()->GetV8ContextDataCount());
}

TEST_F(V8ContextTrackerInternalTearDownOrderTest, LocalBeforeRemote) {
  // Tear down the main |process|. This should tear down everything.
  process_data_->TearDown();
  EXPECT_EQ(0u, data_store()->GetExecutionContextDataCount());
  EXPECT_EQ(0u, data_store()->GetRemoteFrameDataCount());
  EXPECT_EQ(0u, data_store()->GetV8ContextDataCount());

  // Tearing down the |other_process| should do nothing.
  other_process_data_->TearDown();
  EXPECT_EQ(0u, data_store()->GetExecutionContextDataCount());
  EXPECT_EQ(0u, data_store()->GetRemoteFrameDataCount());
  EXPECT_EQ(0u, data_store()->GetV8ContextDataCount());
}

}  // namespace internal
}  // namespace v8_memory
}  // namespace performance_manager
