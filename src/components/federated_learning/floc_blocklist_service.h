// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_FEDERATED_LEARNING_FLOC_BLOCKLIST_SERVICE_H_
#define COMPONENTS_FEDERATED_LEARNING_FLOC_BLOCKLIST_SERVICE_H_

#include <stdint.h>

#include "base/callback.h"
#include "base/files/file_path.h"
#include "base/memory/scoped_refptr.h"
#include "base/memory/weak_ptr.h"
#include "base/observer_list.h"
#include "base/optional.h"
#include "base/version.h"
#include "components/federated_learning/floc_id.h"

namespace base {
class SequencedTaskRunner;
}  // namespace base

namespace federated_learning {

// Responsible for loading the blocklist of flocs that are downloaded through
// the component updater.
//
// File reading and parsing is posted to |background_task_runner_|.
class FlocBlocklistService {
 public:
  using FilterByBlocklistCallback = base::OnceCallback<void(FlocId)>;

  class Observer {
   public:
    virtual void OnBlocklistFileReady() = 0;
  };

  FlocBlocklistService();
  virtual ~FlocBlocklistService();

  FlocBlocklistService(const FlocBlocklistService&) = delete;
  FlocBlocklistService& operator=(const FlocBlocklistService&) = delete;

  // Adds/Removes an Observer.
  void AddObserver(Observer* observer);
  void RemoveObserver(Observer* observer);

  bool IsBlocklistFileReady() const;

  // Virtual for testing.
  virtual void OnBlocklistFileReady(const base::FilePath& file_path,
                                    const base::Version& version);

  // Virtual for testing.
  virtual void FilterByBlocklist(
      const FlocId& unfiltered_floc,
      const base::Optional<base::Version>& version_to_validate,
      FilterByBlocklistCallback callback);

  void SetBackgroundTaskRunnerForTesting(
      scoped_refptr<base::SequencedTaskRunner> background_task_runner);

 private:
  friend class FlocBlocklistServiceTest;
  friend class FlocIdProviderUnitTest;
  friend class FlocIdProviderWithCustomizedServicesBrowserTest;

  // Runner for tasks that do not influence user experience.
  scoped_refptr<base::SequencedTaskRunner> background_task_runner_;

  base::ObserverList<Observer>::Unchecked observers_;

  bool first_file_ready_seen_ = false;
  base::FilePath blocklist_file_path_;
  base::Version blocklist_version_;

  base::WeakPtrFactory<FlocBlocklistService> weak_ptr_factory_;
};

}  // namespace federated_learning

#endif  // COMPONENTS_FEDERATED_LEARNING_FLOC_BLOCKLIST_SERVICE_H_
