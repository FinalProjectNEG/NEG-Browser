// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Internal data structures used by V8ContextTracker. These are only exposed in
// a header for testing. Everything in this header lives in an "internal"
// namespace so as not to pollute the "v8_memory", which houses the actual
// consumer API.

#ifndef COMPONENTS_PERFORMANCE_MANAGER_V8_MEMORY_V8_CONTEXT_TRACKER_INTERNAL_H_
#define COMPONENTS_PERFORMANCE_MANAGER_V8_MEMORY_V8_CONTEXT_TRACKER_INTERNAL_H_

#include <memory>
#include <set>

#include "base/compiler_specific.h"
#include "base/containers/linked_list.h"
#include "base/optional.h"
#include "base/util/type_safety/pass_key.h"
#include "components/performance_manager/graph/node_attached_data_impl.h"
#include "components/performance_manager/graph/process_node_impl.h"
#include "components/performance_manager/v8_memory/v8_context_tracker.h"
#include "components/performance_manager/v8_memory/v8_context_tracker_types.h"
#include "third_party/blink/public/common/tokens/tokens.h"

namespace performance_manager {
namespace v8_memory {
namespace internal {

using ExecutionContextState = V8ContextTracker::ExecutionContextState;
using V8ContextState = V8ContextTracker::V8ContextState;

// Forward declarations.
class ExecutionContextData;
class ProcessData;
class RemoteFrameData;
class V8ContextData;

// A comparator for "Data" objects that compares by token.
template <typename DataType, typename TokenType>
struct TokenComparator {
  using is_transparent = int;
  static const TokenType& GetToken(const TokenType& token) { return token; }
  static const TokenType& GetToken(const std::unique_ptr<DataType>& data) {
    return data->GetToken();
  }
  template <typename Type1, typename Type2>
  bool operator()(const Type1& obj1, const Type2& obj2) const {
    return GetToken(obj1) < GetToken(obj2);
  }
};

////////////////////////////////////////////////////////////////////////////////
// ExecutionContextData declaration:

// Internal wrapper of ExecutionContextState. Augments with additional data
// needed for the implementation. Since these objects also need to be tracked
// per-process, they are kept in a process-associated doubly-linked list.
class ExecutionContextData : public base::LinkNode<ExecutionContextData>,
                             public ExecutionContextState {
 public:
  using Comparator =
      TokenComparator<ExecutionContextData, blink::ExecutionContextToken>;

  ExecutionContextData() = delete;
  ExecutionContextData(const ExecutionContextData&) = delete;
  ExecutionContextData(
      ProcessData* process_data,
      const blink::ExecutionContextToken& token,
      const base::Optional<IframeAttributionData> iframe_attribution_data);
  ExecutionContextData& operator=(const ExecutionContextData&) = delete;
  ~ExecutionContextData() override;

  // Simple accessors.
  ProcessData* process_data() const { return process_data_; }
  RemoteFrameData* remote_frame_data() { return remote_frame_data_; }
  size_t v8_context_count() const { return v8_context_count_; }

  // For consistency, all Data objects have a GetToken() function.
  const blink::ExecutionContextToken& GetToken() const { return token; }

  // Returns true if this object is currently being tracked (it is in
  // ProcessData::execution_context_datas_, and
  // V8ContextTrackerDataStore::global_execution_context_datas_).
  WARN_UNUSED_RESULT bool IsTracked() const;

  // Returns true if this object *should* be destroyed (there are no references
  // to it keeping it alive).
  WARN_UNUSED_RESULT bool ShouldDestroy() const;

  // Manages remote frame data associated with this ExecutionContextData.
  void SetRemoteFrameData(util::PassKey<RemoteFrameData>,
                          RemoteFrameData* remote_frame_data);
  WARN_UNUSED_RESULT bool ClearRemoteFrameData(util::PassKey<RemoteFrameData>);

  // Increments |v8_context_count_|.
  void IncrementV8ContextCount(util::PassKey<V8ContextData>);

  // Decrements |v8_context_count_|, and returns true if the object has
  // transitioned to "ShouldDestroy".
  WARN_UNUSED_RESULT bool DecrementV8ContextCount(util::PassKey<V8ContextData>);

 private:
  ProcessData* const process_data_;

  RemoteFrameData* remote_frame_data_ = nullptr;

  // The count of V8ContextDatas keeping this object alive.
  size_t v8_context_count_ = 0;
};

////////////////////////////////////////////////////////////////////////////////
// RemoteFrameData declaration:

// Represents data about an ExecutionCOntext from the point of view of the
// parent frame that owns it.
class RemoteFrameData : public base::LinkNode<RemoteFrameData> {
 public:
  using Comparator = TokenComparator<RemoteFrameData, blink::RemoteFrameToken>;
  using PassKey = util::PassKey<RemoteFrameData>;

  RemoteFrameData() = delete;
  RemoteFrameData(ProcessData* process_data,
                  const blink::RemoteFrameToken& token,
                  ExecutionContextData* execution_context_data);
  RemoteFrameData(const RemoteFrameData&) = delete;
  RemoteFrameData& operator=(const RemoteFrameData&) = delete;
  ~RemoteFrameData();

  // Simple accessors.
  ProcessData* process_data() const { return process_data_; }
  ExecutionContextData* execution_context_data() const {
    return execution_context_data_;
  }

  // For consistency, all Data objects have a GetToken() function.
  const blink::RemoteFrameToken& GetToken() const { return token_; }

  // Returns true if this object is currently being tracked (it is in
  // ProcessData::remote_frame_datas_, and
  // V8ContextTrackerDataStore::global_remote_frame_datas_).
  WARN_UNUSED_RESULT bool IsTracked() const;

 private:
  ProcessData* const process_data_;
  const blink::RemoteFrameToken token_;
  ExecutionContextData* const execution_context_data_;
};

////////////////////////////////////////////////////////////////////////////////
// V8ContextData declaration:

// Internal wrapper of V8ContextState. Augments with additional data needed for
// the implementation.
class V8ContextData : public base::LinkNode<V8ContextData>,
                      public V8ContextState {
 public:
  using Comparator = TokenComparator<V8ContextData, blink::V8ContextToken>;
  using PassKey = util::PassKey<V8ContextData>;

  V8ContextData() = delete;
  V8ContextData(ProcessData* process_data,
                const V8ContextDescription& description,
                ExecutionContextData* execution_context_data);
  V8ContextData(const V8ContextData&) = delete;
  V8ContextData& operator=(const V8ContextData&) = delete;
  ~V8ContextData() override;

  // Simple accessors.
  ProcessData* process_data() const { return process_data_; }

  // For consistency, all Data objects have a GetToken() function.
  const blink::V8ContextToken& GetToken() const { return description.token; }

  // Returns true if this object is currently being tracked (its in
  // ProcessData::v8_context_datas_, and
  // V8ContextTrackerDataStore::global_v8_context_datas_).
  WARN_UNUSED_RESULT bool IsTracked() const;

  // Returns the ExecutionContextData associated with this V8ContextData.
  ExecutionContextData* GetExecutionContextData() const;

 private:
  ProcessData* const process_data_;
};

////////////////////////////////////////////////////////////////////////////////
// ProcessData declaration:

class ProcessData : public NodeAttachedDataImpl<ProcessData> {
 public:
  struct Traits : public NodeAttachedDataInMap<ProcessNodeImpl> {};

  explicit ProcessData(const ProcessNodeImpl* process_node);
  ~ProcessData() override;

  // Simple accessors.
  V8ContextTrackerDataStore* data_store() const { return data_store_; }

  // Tears down this ProcessData by ensuring that all associated
  // ExecutionContextDatas and V8ContextDatas are cleaned up. This must be
  // called *prior* to the destructor being invoked.
  void TearDown();

  // Adds the provided object to the list of process-associated objects. The
  // object must not be part of a list, its process data must match this one,
  // and it must return false for "ShouldDestroy" (if applicable). For removal,
  // the object must be part of a list, the process data must match this one and
  // "ShouldDestroy" must return false.
  void Add(util::PassKey<V8ContextTrackerDataStore>,
           ExecutionContextData* ec_data);
  void Add(util::PassKey<V8ContextTrackerDataStore>, RemoteFrameData* rf_data);
  void Add(util::PassKey<V8ContextTrackerDataStore>, V8ContextData* v8_data);
  void Remove(util::PassKey<V8ContextTrackerDataStore>,
              ExecutionContextData* ec_data);
  void Remove(util::PassKey<V8ContextTrackerDataStore>,
              RemoteFrameData* rf_data);
  void Remove(util::PassKey<V8ContextTrackerDataStore>, V8ContextData* v8_data);

 private:
  // Used to initialize |data_store_| at construction.
  static V8ContextTrackerDataStore* GetDataStore(
      const ProcessNodeImpl* process_node) {
    return V8ContextTracker::GetFromGraph(process_node->graph())->data_store();
  }

  // Pointer to the DataStore that implicitly owns us.
  V8ContextTrackerDataStore* const data_store_;

  // List of ExecutionContextDatas associated with this process.
  base::LinkedList<ExecutionContextData> execution_context_datas_;

  // List of RemoteFrameDatas associated with this process.
  base::LinkedList<RemoteFrameData> remote_frame_datas_;

  // List of V8ContextDatas associated with this process.
  base::LinkedList<V8ContextData> v8_context_datas_;
};

////////////////////////////////////////////////////////////////////////////////
// V8ContextTrackerDataStore declaration:

// This class acts as the owner of all tracked objects. Objects are created
// in isolation, and ownership passed to this object. Management of all
// per-process lists is centralized through this object.
class V8ContextTrackerDataStore {
 public:
  using PassKey = util::PassKey<V8ContextTrackerDataStore>;

  V8ContextTrackerDataStore();
  ~V8ContextTrackerDataStore();

  // Passes ownership of an object. An object with the same token must not
  // already exist ("Get" should return nullptr). Note that when passing an
  // |ec_data| to the impl that "ShouldDestroy" should return false.
  void Pass(std::unique_ptr<ExecutionContextData> ec_data);
  void Pass(std::unique_ptr<RemoteFrameData> rf_data);
  void Pass(std::unique_ptr<V8ContextData> v8_data);

  // Looks up owned objects by token.
  ExecutionContextData* Get(const blink::ExecutionContextToken& token);
  RemoteFrameData* Get(const blink::RemoteFrameToken& token);
  V8ContextData* Get(const blink::V8ContextToken& token);

  // Destroys objects by token. They must exist ("Get" should return non
  // nullptr).
  void Destroy(const blink::ExecutionContextToken& token);
  void Destroy(const blink::RemoteFrameToken& token);
  void Destroy(const blink::V8ContextToken& token);

  size_t GetExecutionContextDataCount() const {
    return global_execution_context_datas_.size();
  }
  size_t GetRemoteFrameDataCount() const {
    return global_remote_frame_datas_.size();
  }
  size_t GetV8ContextDataCount() const {
    return global_v8_context_datas_.size();
  }

 private:
  // Browser wide registry of ExecutionContextData objects.
  std::set<std::unique_ptr<ExecutionContextData>,
           ExecutionContextData::Comparator>
      global_execution_context_datas_;

  // Browser-wide registry of RemoteFrameData objects.
  std::set<std::unique_ptr<RemoteFrameData>, RemoteFrameData::Comparator>
      global_remote_frame_datas_;

  // Browser wide registry of V8ContextData objects.
  std::set<std::unique_ptr<V8ContextData>, V8ContextData::Comparator>
      global_v8_context_datas_;
};

}  // namespace internal
}  // namespace v8_memory
}  // namespace performance_manager

#endif  // COMPONENTS_PERFORMANCE_MANAGER_V8_MEMORY_V8_CONTEXT_TRACKER_INTERNAL_H_
