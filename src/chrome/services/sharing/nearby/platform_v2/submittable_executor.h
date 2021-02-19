// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_SERVICES_SHARING_NEARBY_PLATFORM_V2_SUBMITTABLE_EXECUTOR_H_
#define CHROME_SERVICES_SHARING_NEARBY_PLATFORM_V2_SUBMITTABLE_EXECUTOR_H_

#include <atomic>

#include "base/synchronization/lock.h"
#include "base/synchronization/waitable_event.h"
#include "base/task_runner.h"
#include "base/thread_annotations.h"
#include "chrome/services/sharing/nearby/platform_v2/atomic_boolean.h"
#include "third_party/nearby/src/cpp/platform_v2/api/submittable_executor.h"

namespace location {
namespace nearby {
namespace chrome {

class SubmittableExecutor : public api::SubmittableExecutor {
 public:
  explicit SubmittableExecutor(scoped_refptr<base::TaskRunner> task_runner);
  ~SubmittableExecutor() override;

  SubmittableExecutor(const SubmittableExecutor&) = delete;
  SubmittableExecutor& operator=(const SubmittableExecutor&) = delete;

  // api::SubmittableExecutor:
  bool DoSubmit(Runnable&& runnable) override;
  void Execute(Runnable&& runnable) override;
  void Shutdown() override;
  int GetTid(int index) const override;

 private:
  // Directly calls run() on |runnable|. This is only meant to be posted as an
  // asynchronous task within Execute().
  void RunTask(Runnable&& runnable);

  base::Lock lock_;
  // Tracks number of incomplete tasks. Accessed from different threads through
  // public APIs and task_runner_.
  int num_incomplete_tasks_ GUARDED_BY(lock_) = 0;
  // Tracks if the executor has been shutdown. Accessed from different threads
  // through public APIs and task_runner_.
  bool is_shut_down_ GUARDED_BY(lock_) = false;

  // last_task_completed_ is used to notify destructor when the last task has
  // completed.
  base::WaitableEvent last_task_completed_;

  scoped_refptr<base::TaskRunner> task_runner_;
};

}  // namespace chrome
}  // namespace nearby
}  // namespace location

#endif  // CHROME_SERVICES_SHARING_NEARBY_PLATFORM_V2_SUBMITTABLE_EXECUTOR_H_
