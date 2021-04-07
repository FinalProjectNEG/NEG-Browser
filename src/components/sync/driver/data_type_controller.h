// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_SYNC_DRIVER_DATA_TYPE_CONTROLLER_H__
#define COMPONENTS_SYNC_DRIVER_DATA_TYPE_CONTROLLER_H__

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "base/callback.h"
#include "base/location.h"
#include "base/memory/weak_ptr.h"
#include "base/sequence_checker.h"
#include "components/sync/base/model_type.h"
#include "components/sync/engine/cycle/status_counters.h"
#include "components/sync/engine/shutdown_reason.h"
#include "components/sync/model/data_type_error_handler.h"

namespace syncer {

struct ConfigureContext;
class ModelTypeConfigurer;
class SyncError;

// DataTypeControllers are responsible for managing the state of a single data
// type. They are not thread safe and should only be used on the UI thread.
class DataTypeController : public base::SupportsWeakPtr<DataTypeController> {
 public:
  enum State {
    NOT_RUNNING,     // The controller has never been started or has previously
                     // been stopped.  Must be in this state to start.
    MODEL_STARTING,  // The model is loading.
    MODEL_LOADED,    // The model has finished loading and can start running.
    RUNNING,         // The controller is running and the data type is
                     // in sync with the cloud.
    STOPPING,        // The controller is in the process of stopping
                     // and is waiting for dependent services to stop.
    FAILED           // The controller was started but encountered an error.
  };

  // Returned from RegisterWithBackend.
  enum RegisterWithBackendResult {
    // Used when RegisterWithBackend is called on an already-registered type.
    // TODO(crbug.com/647505): Get rid of this entry entirely if possible.
    REGISTRATION_IGNORED,
    // Indicates that the initial download for this type is already complete.
    TYPE_ALREADY_DOWNLOADED,
    // Indicates that the initial download for this type still needs to be done.
    TYPE_NOT_YET_DOWNLOADED,
  };

  // Note: This seems like it should be a OnceCallback, but it can actually be
  // called multiple times in the case of errors.
  using ModelLoadCallback =
      base::RepeatingCallback<void(ModelType, const SyncError&)>;

  using StopCallback = base::OnceClosure;

  using AllNodesCallback =
      base::OnceCallback<void(const ModelType,
                              std::unique_ptr<base::ListValue>)>;

  using StatusCountersCallback =
      base::OnceCallback<void(ModelType, const StatusCounters&)>;

  using TypeMap = std::map<ModelType, std::unique_ptr<DataTypeController>>;
  using TypeVector = std::vector<std::unique_ptr<DataTypeController>>;

  static std::string StateToString(State state);

  virtual ~DataTypeController();

  // Begins asynchronous operation of loading the model to get it ready for
  // activation. Once the models are loaded the callback will be invoked with
  // the result. If the models are already loaded it is safe to call the
  // callback right away. Else the callback needs to be stored and called when
  // the models are ready.
  virtual void LoadModels(const ConfigureContext& configure_context,
                          const ModelLoadCallback& model_load_callback) = 0;

  // Registers with sync backend if needed. This function is called by
  // DataTypeManager before downloading initial data. Returns whether the
  // initial download for this type is already complete.
  // TODO(crbug.com/647505): Rename this function to ActivateDataType().
  virtual RegisterWithBackendResult RegisterWithBackend(
      ModelTypeConfigurer* configurer) = 0;

  // Called by DataTypeManager to deactivate the controlled data type.
  // See comments for ModelAssociationManager::OnSingleDataTypeWillStop.
  virtual void DeactivateDataType(ModelTypeConfigurer* configurer) = 0;

  // Stops the data type. If LoadModels() has not completed it will enter
  // STOPPING state first and eventually STOPPED. Once stopped, |callback| will
  // be run. |callback| must not be null.
  //
  // NOTE: Stop() should be called after sync backend machinery has stopped
  // routing changes to this data type. Stop() should ensure the data type
  // logic shuts down gracefully by flushing remaining changes and calling
  // StopSyncing on the SyncableService. This assumes no changes will ever
  // propagate from sync again from point where Stop() is called.
  virtual void Stop(ShutdownReason shutdown_reason, StopCallback callback) = 0;

  // Name of this data type.  For logging purposes only.
  std::string name() const { return ModelTypeToString(type()); }

  // Current state of the data type controller.
  virtual State state() const = 0;

  // Unique model type for this data type controller.
  ModelType type() const { return type_; }

  // Whether preconditions are met for the datatype to start. This is useful for
  // example if the datatype depends on certain user preferences other than the
  // ones for sync settings themselves.
  enum class PreconditionState {
    kPreconditionsMet,
    kMustStopAndClearData,
    kMustStopAndKeepData,
  };
  virtual PreconditionState GetPreconditionState() const;

  // Returns a ListValue representing all nodes for this data type through
  // |callback| on this thread. Can only be called if state() != NOT_RUNNING.
  // Used for populating nodes in Sync Node Browser of chrome://sync-internals.
  virtual void GetAllNodes(AllNodesCallback callback) = 0;

  // Collects StatusCounters for this datatype and passes them to |callback|.
  // Used to display entity counts in chrome://sync-internals. Can be called
  // only if state() != NOT_RUNNING.
  virtual void GetStatusCounters(StatusCountersCallback callback) = 0;

  // Records entities count and estimated memory usage of the type into
  // histograms. Can be called only if state() != NOT_RUNNING.
  virtual void RecordMemoryUsageAndCountsHistograms() = 0;

 protected:
  explicit DataTypeController(ModelType type);

  // Allows subclasses to DCHECK that they're on the correct sequence.
  // TODO(crbug.com/846238): Rename this to CalledOnValidSequence.
  bool CalledOnValidThread() const;

 private:
  // The type this object is responsible for controlling.
  const ModelType type_;

  // Used to check that functions are called on the correct sequence.
  base::SequenceChecker sequence_checker_;
};

}  // namespace syncer

#endif  // COMPONENTS_SYNC_DRIVER_DATA_TYPE_CONTROLLER_H__
