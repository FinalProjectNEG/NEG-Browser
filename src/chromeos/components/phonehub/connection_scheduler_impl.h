// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROMEOS_COMPONENTS_PHONEHUB_CONNECTION_SCHEDULER_IMPL_H_
#define CHROMEOS_COMPONENTS_PHONEHUB_CONNECTION_SCHEDULER_IMPL_H_

#include "base/memory/weak_ptr.h"
#include "base/time/time.h"
#include "chromeos/components/phonehub/connection_scheduler.h"
#include "chromeos/components/phonehub/feature_status.h"
#include "chromeos/components/phonehub/feature_status_provider.h"
#include "net/base/backoff_entry.h"

namespace chromeos {
namespace phonehub {

class ConnectionManager;

// ConnectionScheduler implementation that schedules calls to ConnectionManager
// in order to establish a connection to the user's phone.
class ConnectionSchedulerImpl : public ConnectionScheduler,
                                public FeatureStatusProvider::Observer {
 public:
  ConnectionSchedulerImpl(ConnectionManager* connection_manager,
                          FeatureStatusProvider* feature_status_provider);
  ~ConnectionSchedulerImpl() override;

  void ScheduleConnectionNow() override;

 private:
  friend class ConnectionSchedulerImplTest;

  // FeatureStatusProvider::Observer:
  void OnFeatureStatusChanged() override;

  // Invalidate all pending backoff attempts.
  void ClearBackoffAttempts();

  // Test only functions.
  base::TimeDelta GetCurrentBackoffDelayTimeForTesting();
  int GetBackoffFailureCountForTesting();

  ConnectionManager* connection_manager_;
  FeatureStatusProvider* feature_status_provider_;
  // Provides us the backoff timers for RequestConnection().
  net::BackoffEntry retry_backoff_;
  FeatureStatus current_feature_status_;
  base::WeakPtrFactory<ConnectionSchedulerImpl> weak_ptr_factory_{this};
};

}  // namespace phonehub
}  // namespace chromeos

#endif  // CHROMEOS_COMPONENTS_PHONEHUB_CONNECTION_SCHEDULER_IMPL_H_