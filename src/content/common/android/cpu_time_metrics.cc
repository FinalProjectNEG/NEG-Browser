// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/common/android/cpu_time_metrics.h"

#include <stdint.h>

#include <atomic>
#include <memory>
#include <utility>

#include "base/bind_helpers.h"
#include "base/command_line.h"
#include "base/containers/flat_map.h"
#include "base/cpu.h"
#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/metrics/histogram_macros.h"
#include "base/no_destructor.h"
#include "base/process/process_metrics.h"
#include "base/sequence_checker.h"
#include "base/strings/pattern.h"
#include "base/strings/string_util.h"
#include "base/task/current_thread.h"
#include "base/task/post_task.h"
#include "base/task/task_observer.h"
#include "base/threading/platform_thread.h"
#include "base/threading/thread_id_name_manager.h"
#include "base/threading/thread_task_runner_handle.h"
#include "content/public/common/content_switches.h"
#include "content/public/common/process_type.h"

namespace content {
namespace {

// Histogram macros expect an enum class with kMaxValue. Because
// content::ProcessType cannot be migrated to this style at the moment, we
// specify a separate version here. Keep in sync with content::ProcessType.
// TODO(eseckler): Replace with content::ProcessType after its migration.
enum class ProcessTypeForUma {
  kUnknown = 1,
  kBrowser,
  kRenderer,
  kPluginDeprecated,
  kWorkerDeprecated,
  kUtility,
  kZygote,
  kSandboxHelper,
  kGpu,
  kPpapiPlugin,
  kPpapiBroker,
  kMaxValue = kPpapiBroker,
};

static_assert(static_cast<int>(ProcessTypeForUma::kMaxValue) ==
                  PROCESS_TYPE_PPAPI_BROKER,
              "ProcessTypeForUma and CurrentProcessType() require updating");

ProcessTypeForUma CurrentProcessType() {
  std::string process_type =
      base::CommandLine::ForCurrentProcess()->GetSwitchValueASCII(
          switches::kProcessType);
  if (process_type.empty())
    return ProcessTypeForUma::kBrowser;
  if (process_type == switches::kRendererProcess)
    return ProcessTypeForUma::kRenderer;
  if (process_type == switches::kUtilityProcess)
    return ProcessTypeForUma::kUtility;
  if (process_type == switches::kSandboxIPCProcess)
    return ProcessTypeForUma::kSandboxHelper;
  if (process_type == switches::kGpuProcess)
    return ProcessTypeForUma::kGpu;
  if (process_type == switches::kPpapiPluginProcess)
    return ProcessTypeForUma::kPpapiPlugin;
  if (process_type == switches::kPpapiBrokerProcess)
    return ProcessTypeForUma::kPpapiBroker;
  NOTREACHED() << "Unexpected process type: " << process_type;
  return ProcessTypeForUma::kUnknown;
}

const char* GetPerThreadHistogramNameForProcessType(ProcessTypeForUma type) {
  switch (type) {
    case ProcessTypeForUma::kBrowser:
      return "Power.CpuTimeSecondsPerThreadType.Browser";
    case ProcessTypeForUma::kRenderer:
      return "Power.CpuTimeSecondsPerThreadType.Renderer";
    case ProcessTypeForUma::kGpu:
      return "Power.CpuTimeSecondsPerThreadType.GPU";
    default:
      return "Power.CpuTimeSecondsPerThreadType.Other";
  }
}

std::string GetPerCoreCpuTimeHistogramName(ProcessTypeForUma process_type,
                                           base::CPU::CoreType core_type,
                                           bool is_approximate) {
  std::string process_suffix;
  switch (process_type) {
    case ProcessTypeForUma::kBrowser:
      process_suffix = "Browser";
      break;
    case ProcessTypeForUma::kRenderer:
      process_suffix = "Renderer";
      break;
    case ProcessTypeForUma::kGpu:
      process_suffix = "GPU";
      break;
    default:
      process_suffix = "Other";
      break;
  }

  std::string cpu_suffix;
  switch (core_type) {
    case base::CPU::CoreType::kUnknown:
      cpu_suffix = "Unknown";
      break;
    case base::CPU::CoreType::kOther:
      cpu_suffix = "Other";
      break;
    case base::CPU::CoreType::kSymmetric:
      cpu_suffix = "Symmetric";
      break;
    case base::CPU::CoreType::kBigLittle_Little:
      cpu_suffix = "BigLittle.Little";
      break;
    case base::CPU::CoreType::kBigLittle_Big:
      cpu_suffix = "BigLittle.Big";
      break;
    case base::CPU::CoreType::kBigLittleBigger_Little:
      cpu_suffix = "BigLittleBigger.Little";
      break;
    case base::CPU::CoreType::kBigLittleBigger_Big:
      cpu_suffix = "BigLittleBigger.Big";
      break;
    case base::CPU::CoreType::kBigLittleBigger_Bigger:
      cpu_suffix = "BigLittleBigger.Bigger";
      break;
  }

  std::string prefix = std::string("Power.") +
                       (is_approximate ? "Approx" : "") +
                       "CpuTimeSecondsPerCoreTypeAndFrequency";

  return base::JoinString({prefix, cpu_suffix, process_suffix}, ".");
}

// Keep in sync with CpuTimeMetricsThreadType in
// //tools/metrics/histograms/enums.xml.
enum class CpuTimeMetricsThreadType {
  kUnattributedThread = 0,
  kOtherThread,
  kMainThread,
  kIOThread,
  kThreadPoolBackgroundWorkerThread,
  kThreadPoolForegroundWorkerThread,
  kThreadPoolServiceThread,
  kCompositorThread,
  kCompositorTileWorkerThread,
  kVizCompositorThread,
  kRendererUnspecifiedWorkerThread,
  kRendererDedicatedWorkerThread,
  kRendererSharedWorkerThread,
  kRendererAnimationAndPaintWorkletThread,
  kRendererServiceWorkerThread,
  kRendererAudioWorkletThread,
  kRendererFileThread,
  kRendererDatabaseThread,
  kRendererOfflineAudioRenderThread,
  kRendererReverbConvolutionBackgroundThread,
  kRendererHRTFDatabaseLoaderThread,
  kRendererAudioEncoderThread,
  kRendererVideoEncoderThread,
  kMemoryInfraThread,
  kSamplingProfilerThread,
  kNetworkServiceThread,
  kAudioThread,
  kInProcessUtilityThread,
  kInProcessRendererThread,
  kInProcessGpuThread,
  kMaxValue = kInProcessGpuThread,
};

CpuTimeMetricsThreadType GetThreadTypeFromName(const char* const thread_name) {
  if (!thread_name)
    return CpuTimeMetricsThreadType::kOtherThread;

  if (base::MatchPattern(thread_name, "Cr*Main")) {
    return CpuTimeMetricsThreadType::kMainThread;
  } else if (base::MatchPattern(thread_name, "Chrome*IOThread")) {
    return CpuTimeMetricsThreadType::kIOThread;
  } else if (base::MatchPattern(thread_name, "ThreadPool*Foreground*")) {
    return CpuTimeMetricsThreadType::kThreadPoolForegroundWorkerThread;
  } else if (base::MatchPattern(thread_name, "ThreadPool*Background*")) {
    return CpuTimeMetricsThreadType::kThreadPoolBackgroundWorkerThread;
  } else if (base::MatchPattern(thread_name, "ThreadPoolService*")) {
    return CpuTimeMetricsThreadType::kThreadPoolServiceThread;
  } else if (base::MatchPattern(thread_name, "Compositor")) {
    return CpuTimeMetricsThreadType::kCompositorThread;
  } else if (base::MatchPattern(thread_name, "CompositorTileWorker*")) {
    return CpuTimeMetricsThreadType::kCompositorTileWorkerThread;
  } else if (base::MatchPattern(thread_name, "VizCompositor*")) {
    return CpuTimeMetricsThreadType::kVizCompositorThread;
  } else if (base::MatchPattern(thread_name, "unspecified worker*")) {
    return CpuTimeMetricsThreadType::kRendererUnspecifiedWorkerThread;
  } else if (base::MatchPattern(thread_name, "DedicatedWorker*")) {
    return CpuTimeMetricsThreadType::kRendererDedicatedWorkerThread;
  } else if (base::MatchPattern(thread_name, "SharedWorker*")) {
    return CpuTimeMetricsThreadType::kRendererSharedWorkerThread;
  } else if (base::MatchPattern(thread_name, "AnimationWorklet*")) {
    return CpuTimeMetricsThreadType::kRendererAnimationAndPaintWorkletThread;
  } else if (base::MatchPattern(thread_name, "ServiceWorker*")) {
    return CpuTimeMetricsThreadType::kRendererServiceWorkerThread;
  } else if (base::MatchPattern(thread_name, "AudioWorklet*")) {
    return CpuTimeMetricsThreadType::kRendererAudioWorkletThread;
  } else if (base::MatchPattern(thread_name, "File thread")) {
    return CpuTimeMetricsThreadType::kRendererFileThread;
  } else if (base::MatchPattern(thread_name, "Database thread")) {
    return CpuTimeMetricsThreadType::kRendererDatabaseThread;
  } else if (base::MatchPattern(thread_name, "OfflineAudioRender*")) {
    return CpuTimeMetricsThreadType::kRendererOfflineAudioRenderThread;
  } else if (base::MatchPattern(thread_name, "Reverb convolution*")) {
    return CpuTimeMetricsThreadType::kRendererReverbConvolutionBackgroundThread;
  } else if (base::MatchPattern(thread_name, "HRTF*")) {
    return CpuTimeMetricsThreadType::kRendererHRTFDatabaseLoaderThread;
  } else if (base::MatchPattern(thread_name, "Audio encoder*")) {
    return CpuTimeMetricsThreadType::kRendererAudioEncoderThread;
  } else if (base::MatchPattern(thread_name, "Video encoder*")) {
    return CpuTimeMetricsThreadType::kRendererVideoEncoderThread;
  } else if (base::MatchPattern(thread_name, "MemoryInfra")) {
    return CpuTimeMetricsThreadType::kMemoryInfraThread;
  } else if (base::MatchPattern(thread_name, "StackSamplingProfiler")) {
    return CpuTimeMetricsThreadType::kSamplingProfilerThread;
  } else if (base::MatchPattern(thread_name, "NetworkService")) {
    return CpuTimeMetricsThreadType::kNetworkServiceThread;
  } else if (base::MatchPattern(thread_name, "AudioThread")) {
    return CpuTimeMetricsThreadType::kAudioThread;
  } else if (base::MatchPattern(thread_name, "Chrome_InProcUtilityThread")) {
    return CpuTimeMetricsThreadType::kInProcessUtilityThread;
  } else if (base::MatchPattern(thread_name, "Chrome_InProcRendererThread")) {
    return CpuTimeMetricsThreadType::kInProcessRendererThread;
  } else if (base::MatchPattern(thread_name, "Chrome_InProcGpuThread")) {
    return CpuTimeMetricsThreadType::kInProcessGpuThread;
  }

  // TODO(eseckler): Also break out Android's RenderThread here somehow?

  return CpuTimeMetricsThreadType::kOtherThread;
}

class TimeInStateReporter {
 public:
  TimeInStateReporter(ProcessTypeForUma process_type,
                      base::CPU::CoreType core_type,
                      bool is_approximate)
      : histogram_(GetPerCoreCpuTimeHistogramName(process_type,
                                                  core_type,
                                                  is_approximate),
                   1,
                   // ScaledLinearHistogram requires buckets of size 1. Each
                   // bucket here represents a range of frequency values.
                   kNumBuckets,
                   kNumBuckets + 1,
                   base::Time::kMicrosecondsPerSecond,
                   base::HistogramBase::kUmaTargetedHistogramFlag) {}

  void AddMicroseconds(int frequency_mhz, int cpu_time_us) {
    int frequency_bucket = frequency_mhz / kBucketSizeMhz;
    histogram_.AddScaledCount(frequency_bucket, cpu_time_us);
  }

 private:
  static constexpr int32_t kMaxFrequencyMhz = 10 * 1000;  // 10 GHz.
  static constexpr int32_t kBucketSizeMhz = 50;  // one bucket for every 50 MHz.
  static constexpr int32_t kNumBuckets = kMaxFrequencyMhz / kBucketSizeMhz;

  base::ScaledLinearHistogram histogram_;
};

// Samples the process's CPU time after a specific number of task were executed
// on the current thread (process main). The number of tasks is a crude proxy
// for CPU activity within this process. We sample more frequently when the
// process is more active, thus ensuring we lose little CPU time attribution
// when the process is terminated, even after it was very active.
class ProcessCpuTimeTaskObserver : public base::TaskObserver {
 public:
  static ProcessCpuTimeTaskObserver* GetInstance() {
    static base::NoDestructor<ProcessCpuTimeTaskObserver> instance;
    return instance.get();
  }

  ProcessCpuTimeTaskObserver()
      : task_runner_(base::CreateSequencedTaskRunner(
            {base::ThreadPool(), base::TaskPriority::BEST_EFFORT,
             // TODO(eseckler): Consider hooking into process shutdown on
             // desktop to reduce metric data loss.
             base::TaskShutdownBehavior::SKIP_ON_SHUTDOWN})),
        process_metrics_(base::ProcessMetrics::CreateCurrentProcessMetrics()),
        process_type_(CurrentProcessType()),
        // The observer is created on the main thread of the process.
        main_thread_id_(base::PlatformThread::CurrentId()) {
    // Browser and GPU processes have a longer lifetime (don't disappear between
    // navigations), and typically execute a large number of small main-thread
    // tasks. For these processes, choose a higher reporting interval.
    if (process_type_ == ProcessTypeForUma::kBrowser ||
        process_type_ == ProcessTypeForUma::kGpu) {
      reporting_interval_ = kReportAfterEveryNTasksPersistentProcess;
    } else {
      reporting_interval_ = kReportAfterEveryNTasksOtherProcess;
    }
    DETACH_FROM_SEQUENCE(thread_pool_);
  }

  // base::TaskObserver implementation:
  void WillProcessTask(const base::PendingTask& pending_task,
                       bool was_blocked_or_low_priority) override {}

  void DidProcessTask(const base::PendingTask& pending_task) override {
    DCHECK_CALLED_ON_VALID_SEQUENCE(main_thread_);
    // We perform the collection from a background thread. Only schedule another
    // one after a reasonably large amount of work was executed after the last
    // collection completed. std::memory_order_relaxed because we only care that
    // we pick up the change back by the posted task eventually.
    if (collection_in_progress_.load(std::memory_order_relaxed))
      return;
    task_counter_++;
    if (task_counter_ == reporting_interval_) {
      // PostTask() applies a barrier, so this will be applied before the thread
      // pool task executes and sets |collection_in_progress_| back to false.
      collection_in_progress_.store(true, std::memory_order_relaxed);
      task_runner_->PostTask(
          FROM_HERE,
          base::BindOnce(
              &ProcessCpuTimeTaskObserver::CollectAndReportCpuTimeOnThreadPool,
              base::Unretained(this)));
      task_counter_ = 0;
    }
  }

  void CollectAndReportCpuTimeOnThreadPool() {
    DCHECK_CALLED_ON_VALID_SEQUENCE(thread_pool_);

    // This might overflow. We only care that it is different for each cycle.
    current_cycle_++;

    // GetCumulativeCPUUsage() may return a negative value if sampling failed.
    base::TimeDelta cumulative_cpu_time =
        process_metrics_->GetCumulativeCPUUsage();
    base::TimeDelta process_cpu_time_delta =
        cumulative_cpu_time - reported_cpu_time_;
    if (process_cpu_time_delta > base::TimeDelta()) {
      UMA_HISTOGRAM_SCALED_ENUMERATION("Power.CpuTimeSecondsPerProcessType",
                                       process_type_,
                                       process_cpu_time_delta.InMicroseconds(),
                                       base::Time::kMicrosecondsPerSecond);
      reported_cpu_time_ = cumulative_cpu_time;
    }

    // Approximate breakdown by CPU core type & frequency. The per-pid
    // time_in_state used by the per-thread breakdown isn't supported by many
    // kernels. This breakdown approximates Chrome's total per
    // core-type/frequency usage by splitting the process's CPU time across
    // cores/frequencies according to global per-core time_in_state values.
    if (base::CPU::GetTimeInState(time_in_state_)) {
      // Compute the total CPU time delta since the last cycle across all
      // clusters and frequencies, so that we can compute proportional deltas in
      // the second loop below.
      base::TimeDelta total_cumulative;
      for (const base::CPU::TimeInStateEntry& entry : time_in_state_) {
        total_cumulative += entry.cumulative_cpu_time;
      }

      base::TimeDelta total_delta =
          total_cumulative - total_reported_time_in_state_;
      total_reported_time_in_state_ = total_cumulative;

      if (process_cpu_time_delta > base::TimeDelta() &&
          total_delta > base::TimeDelta()) {
        for (const base::CPU::TimeInStateEntry& entry : time_in_state_) {
          DCHECK_GT(approximate_time_in_state_reporters_.size(),
                    static_cast<size_t>(entry.core_type));
          std::unique_ptr<TimeInStateReporter>& reporter =
              approximate_time_in_state_reporters_[static_cast<size_t>(
                  entry.core_type)];
          if (!reporter) {
            reporter = std::make_unique<TimeInStateReporter>(
                process_type_, entry.core_type, /*is_approximate=*/true);
          }

          // Compute delta since last cycle per entry.
          uint32_t frequency_mhz = entry.core_frequency_khz / 1000;
          base::TimeDelta& reported_time =
              reported_time_in_state_[std::make_tuple(
                  entry.core_type, entry.cluster_core_index, frequency_mhz)];
          base::TimeDelta time_delta =
              entry.cumulative_cpu_time - reported_time;
          reported_time = entry.cumulative_cpu_time;

          if (time_delta > base::TimeDelta()) {
            // Scale the process's cpu time by each cluster/frequency pair's
            // relative proportion of execution time. We scale by a double value
            // to avoid integer overflow in the presence of large time_delta values.
            uint64_t delta_us = process_cpu_time_delta.InMicroseconds() *
                                (time_delta.InMicroseconds() /
                                 static_cast<double>(total_delta.InMicroseconds()));
            reporter->AddMicroseconds(frequency_mhz, delta_us);
          }
        }
      }
    }

    // Also report a breakdown by thread type.
    base::TimeDelta unattributed_delta = process_cpu_time_delta;
    if (process_metrics_->GetCumulativeCPUUsagePerThread(
            cumulative_thread_times_)) {
      for (const auto& entry : cumulative_thread_times_) {
        base::PlatformThreadId tid = entry.first;
        base::TimeDelta cumulative_time = entry.second;

        auto it_and_inserted = thread_details_.emplace(
            tid, ThreadDetails{base::TimeDelta(), current_cycle_});
        ThreadDetails* thread_details = &it_and_inserted.first->second;

        if (it_and_inserted.second) {
          // New thread.
          thread_details->type = GuessThreadType(tid);
        }

        thread_details->last_updated_cycle = current_cycle_;

        // Skip negative or null values, might be a transient collection error.
        if (cumulative_time <= base::TimeDelta())
          continue;

        if (cumulative_time < thread_details->reported_cpu_time) {
          // PlatformThreadId was likely reused, reset the details.
          thread_details->reported_cpu_time = base::TimeDelta();
          thread_details->type = GuessThreadType(tid);
        }

        base::TimeDelta thread_delta =
            cumulative_time - thread_details->reported_cpu_time;
        unattributed_delta -= thread_delta;

        ReportThreadCpuTimeDelta(thread_details->type, thread_delta);
        thread_details->reported_cpu_time = cumulative_time;
      }

      // Breakdown by CPU core type & frequency.
      if (process_metrics_->GetPerThreadCumulativeCPUTimeInState(
              time_in_state_per_thread_)) {
        auto thread_it = thread_details_.end();
        for (const base::ProcessMetrics::ThreadTimeInState& entry :
             time_in_state_per_thread_) {
          DCHECK_GT(time_in_state_reporters_.size(),
                    static_cast<size_t>(entry.core_type));
          std::unique_ptr<TimeInStateReporter>& reporter =
              time_in_state_reporters_[static_cast<size_t>(entry.core_type)];
          if (!reporter) {
            reporter = std::make_unique<TimeInStateReporter>(
                process_type_, entry.core_type,
                /*is_approximate=*/false);
          }

          if (thread_it == thread_details_.end() ||
              thread_it->first != entry.thread_id) {
            thread_it = thread_details_.find(entry.thread_id);
            if (thread_it == thread_details_.end()) {
              // New thread that we didn't pick up above. We'll report it in the
              // next cycle instead.
              continue;
            }
          }

          uint32_t frequency_mhz = entry.core_frequency_khz / 1000;
          base::TimeDelta& reported_time =
              thread_it->second.reported_time_in_state[std::make_tuple(
                  entry.core_type, entry.cluster_core_index, frequency_mhz)];
          base::TimeDelta time_delta =
              entry.cumulative_cpu_time - reported_time;
          reported_time = entry.cumulative_cpu_time;

          reporter->AddMicroseconds(frequency_mhz, time_delta.InMicroseconds());
        }
      }

      // Erase tracking for threads that have disappeared, as their
      // PlatformThreadId may be reused later.
      for (auto it = thread_details_.begin(); it != thread_details_.end();) {
        if (it->second.last_updated_cycle == current_cycle_) {
          it++;
        } else {
          it = thread_details_.erase(it);
        }
      }
    }

    // Report the difference of the process's total CPU time and all thread's
    // CPU time as unattributed time (e.g. time consumed by threads that died).
    if (unattributed_delta > base::TimeDelta()) {
      ReportThreadCpuTimeDelta(CpuTimeMetricsThreadType::kUnattributedThread,
                               unattributed_delta);
    }

    collection_in_progress_.store(false, std::memory_order_relaxed);
  }

 private:
  using ClusterFrequency = std::tuple<base::CPU::CoreType,
                                      uint32_t /*cluster_core_index*/,
                                      uint32_t /*frequency_mhz*/>;

  struct ThreadDetails {
    base::TimeDelta reported_cpu_time;
    uint32_t last_updated_cycle = 0;
    CpuTimeMetricsThreadType type = CpuTimeMetricsThreadType::kOtherThread;
    base::flat_map<ClusterFrequency, base::TimeDelta /*time_in_state*/>
        reported_time_in_state;
  };

  void ReportThreadCpuTimeDelta(CpuTimeMetricsThreadType type,
                                base::TimeDelta cpu_time_delta) {
    // Histogram name cannot change after being used once. That's ok since this
    // only depends on the process type, which also doesn't change.
    static const char* histogram_name =
        GetPerThreadHistogramNameForProcessType(process_type_);
    UMA_HISTOGRAM_SCALED_ENUMERATION(histogram_name, type,
                                     cpu_time_delta.InMicroseconds(),
                                     base::Time::kMicrosecondsPerSecond);
  }

  CpuTimeMetricsThreadType GuessThreadType(base::PlatformThreadId tid) {
    // Match the main thread by TID, so that this also works for WebView, where
    // the main thread can have an arbitrary name.
    if (tid == main_thread_id_)
      return CpuTimeMetricsThreadType::kMainThread;
    const char* name = base::ThreadIdNameManager::GetInstance()->GetName(tid);
    return GetThreadTypeFromName(name);
  }

  // Sample CPU time after a certain number of main-thread task to balance
  // overhead of sampling and loss at process termination.
  static constexpr int kReportAfterEveryNTasksPersistentProcess = 500;
  static constexpr int kReportAfterEveryNTasksOtherProcess = 100;

  // Accessed on main thread.
  SEQUENCE_CHECKER(main_thread_);
  scoped_refptr<base::SequencedTaskRunner> task_runner_;
  int task_counter_ = 0;
  int reporting_interval_ = 0;  // set in constructor.

  // Accessed on |task_runner_|.
  SEQUENCE_CHECKER(thread_pool_);
  uint32_t current_cycle_ = 0;
  std::unique_ptr<base::ProcessMetrics> process_metrics_;
  ProcessTypeForUma process_type_;
  base::PlatformThreadId main_thread_id_;
  base::TimeDelta reported_cpu_time_;
  base::flat_map<base::PlatformThreadId, ThreadDetails> thread_details_;
  std::array<std::unique_ptr<TimeInStateReporter>,
             static_cast<size_t>(base::CPU::CoreType::kMaxValue) + 1u>
      time_in_state_reporters_ = {};
  std::array<std::unique_ptr<TimeInStateReporter>,
             static_cast<size_t>(base::CPU::CoreType::kMaxValue) + 1u>
      approximate_time_in_state_reporters_ = {};
  base::flat_map<ClusterFrequency, base::TimeDelta /*time_in_state*/>
      reported_time_in_state_;
  base::TimeDelta total_reported_time_in_state_;
  // Stored as instance variables to avoid allocation churn.
  base::ProcessMetrics::CPUUsagePerThread cumulative_thread_times_;
  base::ProcessMetrics::TimeInStatePerThread time_in_state_per_thread_;
  base::CPU::TimeInState time_in_state_;

  // Accessed on both sequences.
  std::atomic<bool> collection_in_progress_;
};

}  // namespace

void SetupCpuTimeMetrics() {
  // May be called multiple times for in-process renderer/utility/GPU processes.
  static bool did_setup = false;
  if (did_setup)
    return;
  base::CurrentThread::Get()->AddTaskObserver(
      ProcessCpuTimeTaskObserver::GetInstance());
  did_setup = true;
}

void SampleCpuTimeMetricsForTesting() {
  ProcessCpuTimeTaskObserver::GetInstance()
      ->CollectAndReportCpuTimeOnThreadPool();
}

}  // namespace content
