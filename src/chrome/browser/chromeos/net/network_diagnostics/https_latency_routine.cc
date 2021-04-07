// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/chromeos/net/network_diagnostics/https_latency_routine.h"

#include <string>
#include <utility>
#include <vector>

#include "base/bind.h"
#include "base/time/default_tick_clock.h"
#include "chrome/browser/chromeos/net/network_diagnostics/network_diagnostics_util.h"
#include "chrome/browser/profiles/profile_manager.h"
#include "content/public/browser/storage_partition.h"
#include "mojo/public/cpp/bindings/receiver.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "net/base/host_port_pair.h"
#include "net/base/net_errors.h"
#include "services/network/public/mojom/network_context.mojom.h"

namespace chromeos {
namespace network_diagnostics {
namespace {

constexpr int kTotalHostsToQuery = 3;
// The length of a random eight letter prefix.
constexpr int kHostPrefixLength = 8;
constexpr int kHttpPort = 80;
constexpr char kHttpsScheme[] = "https://";
constexpr base::TimeDelta ksRequestTimeoutMs =
    base::TimeDelta::FromMilliseconds(5 * 1000);
// Requests taking longer than 1000 ms are problematic.
constexpr base::TimeDelta kProblemLatencyMs =
    base::TimeDelta::FromMilliseconds(1000);
// Requests lasting between 500 ms and 1000 ms are potentially problematic.
constexpr base::TimeDelta kPotentialProblemLatencyMs =
    base::TimeDelta::FromMilliseconds(500);

base::TimeDelta MedianLatency(std::vector<base::TimeDelta>& latencies) {
  if (latencies.size() == 0) {
    return base::TimeDelta::Max();
  }
  std::sort(latencies.begin(), latencies.end());
  if (latencies.size() % 2 != 0) {
    return latencies[latencies.size() / 2];
  }
  auto sum =
      latencies[latencies.size() / 2] + latencies[(latencies.size() + 1) / 2];
  return sum / 2.0;
}

}  // namespace

class HttpsLatencyRoutine::HostResolver
    : public network::ResolveHostClientBase {
 public:
  explicit HostResolver(HttpsLatencyRoutine* https_latency_routine);
  HostResolver(const HostResolver&) = delete;
  HostResolver& operator=(const HostResolver&) = delete;
  ~HostResolver() override;

  // network::mojom::ResolveHostClient:
  void OnComplete(
      int result,
      const net::ResolveErrorInfo& resolve_error_info,
      const base::Optional<net::AddressList>& resolved_addresses) override;

  // Performs the DNS resolution.
  void Run(const std::string& hostname);

  network::mojom::NetworkContext* network_context() const {
    return network_context_;
  }
  Profile* profile() const { return profile_; }
  void set_network_context_for_testing(
      network::mojom::NetworkContext* network_context) {
    network_context_ = network_context;
  }
  void set_profile_for_testing(Profile* profile) { profile_ = profile; }

 private:
  void CreateHostResolver();
  void OnMojoConnectionError();

  Profile* profile_ = nullptr;                                 // Unowned
  network::mojom::NetworkContext* network_context_ = nullptr;  // Unowned
  HttpsLatencyRoutine* https_latency_routine_ = nullptr;       // Unowned
  mojo::Receiver<network::mojom::ResolveHostClient> receiver_{this};
  mojo::Remote<network::mojom::HostResolver> host_resolver_;
};

HttpsLatencyRoutine::HostResolver::HostResolver(
    HttpsLatencyRoutine* https_latency_routine)
    : profile_(util::GetUserProfile()),
      network_context_(
          content::BrowserContext::GetDefaultStoragePartition(profile_)
              ->GetNetworkContext()),
      https_latency_routine_(https_latency_routine) {
  DCHECK(https_latency_routine_);
  DCHECK(network_context_);
}

HttpsLatencyRoutine::HostResolver::~HostResolver() = default;

void HttpsLatencyRoutine::HostResolver::OnComplete(
    int result,
    const net::ResolveErrorInfo& resolve_error_info,
    const base::Optional<net::AddressList>& resolved_addresses) {
  receiver_.reset();

  https_latency_routine_->OnHostResolutionComplete(result, resolve_error_info,
                                                   resolved_addresses);
}

void HttpsLatencyRoutine::HostResolver::Run(const std::string& hostname) {
  if (!host_resolver_) {
    CreateHostResolver();
  }
  DCHECK(host_resolver_);
  DCHECK(!receiver_.is_bound());

  network::mojom::ResolveHostParametersPtr parameters =
      network::mojom::ResolveHostParameters::New();
  parameters->dns_query_type = net::DnsQueryType::A;
  parameters->source = net::HostResolverSource::DNS;
  parameters->cache_usage =
      network::mojom::ResolveHostParameters::CacheUsage::DISALLOWED;

  host_resolver_->ResolveHost(net::HostPortPair(hostname, kHttpPort),
                              net::NetworkIsolationKey::CreateTransient(),
                              std::move(parameters),
                              receiver_.BindNewPipeAndPassRemote());
}

void HttpsLatencyRoutine::HostResolver::CreateHostResolver() {
  host_resolver_.reset();
  network_context()->CreateHostResolver(
      net::DnsConfigOverrides(), host_resolver_.BindNewPipeAndPassReceiver());
  // Disconnect handler will be invoked if the network service crashes.
  host_resolver_.set_disconnect_handler(base::BindOnce(
      &HostResolver::OnMojoConnectionError, base::Unretained(this)));
}

void HttpsLatencyRoutine::HostResolver::OnMojoConnectionError() {
  CreateHostResolver();
  OnComplete(net::ERR_NAME_NOT_RESOLVED, net::ResolveErrorInfo(net::ERR_FAILED),
             base::nullopt);
}

HttpsLatencyRoutine::HttpsLatencyRoutine()
    : tick_clock_(base::DefaultTickClock::GetInstance()),
      hostnames_to_query_dns_(
          util::GetRandomHostsWithSchemeAndGenerate204Path(kTotalHostsToQuery,
                                                           kHostPrefixLength,
                                                           kHttpsScheme)),
      hostnames_to_query_https_(hostnames_to_query_dns_),
      host_resolver_(std::make_unique<HostResolver>(this)),
      http_request_manager_(
          std::make_unique<HttpRequestManager>(host_resolver_->profile())) {
  DCHECK(http_request_manager_);
}

HttpsLatencyRoutine::~HttpsLatencyRoutine() = default;

void HttpsLatencyRoutine::RunRoutine(HttpsLatencyRoutineCallback callback) {
  if (!CanRun()) {
    std::move(callback).Run(verdict(), problems_);
    return;
  }
  routine_completed_callback_ = std::move(callback);
  // Before making HTTPS requests to the hosts, add the IP addresses are added
  // to the DNS cache. This ensures the HTTPS latency does not include DNS
  // resolution time, allowing us to identify issues with HTTPS more precisely.
  AttemptNextResolution();
}

void HttpsLatencyRoutine::AnalyzeResultsAndExecuteCallback() {
  base::TimeDelta median_latency = MedianLatency(latencies_);
  if (!successfully_resolved_hosts_) {
    set_verdict(mojom::RoutineVerdict::kProblem);
    problems_.emplace_back(mojom::HttpsLatencyProblem::kFailedDnsResolutions);
  } else if (failed_connection_) {
    set_verdict(mojom::RoutineVerdict::kProblem);
    problems_.emplace_back(mojom::HttpsLatencyProblem::kFailedHttpsRequests);
  } else if (median_latency <= kProblemLatencyMs &&
             median_latency > kPotentialProblemLatencyMs) {
    set_verdict(mojom::RoutineVerdict::kProblem);
    problems_.emplace_back(mojom::HttpsLatencyProblem::kHighLatency);
  } else if (median_latency > kProblemLatencyMs) {
    set_verdict(mojom::RoutineVerdict::kProblem);
    problems_.emplace_back(mojom::HttpsLatencyProblem::kVeryHighLatency);
  } else {
    set_verdict(mojom::RoutineVerdict::kNoProblem);
  }
  std::move(routine_completed_callback_).Run(verdict(), problems_);
}

void HttpsLatencyRoutine::AttemptNextResolution() {
  std::string hostname = hostnames_to_query_dns_.back();
  hostnames_to_query_dns_.pop_back();
  host_resolver_->Run(hostname);
}

void HttpsLatencyRoutine::OnHostResolutionComplete(
    int result,
    const net::ResolveErrorInfo& resolve_error_info,
    const base::Optional<net::AddressList>& resolved_addresses) {
  bool success = result == net::OK && !resolved_addresses->empty() &&
                 resolved_addresses.has_value();
  if (!success) {
    successfully_resolved_hosts_ = false;
    AnalyzeResultsAndExecuteCallback();
    return;
  }
  if (hostnames_to_query_dns_.size() > 0) {
    AttemptNextResolution();
    return;
  }
  MakeHttpsRequest();
}

void HttpsLatencyRoutine::SetNetworkContextForTesting(
    network::mojom::NetworkContext* network_context) {
  host_resolver_->set_network_context_for_testing(network_context);
}

void HttpsLatencyRoutine::SetProfileForTesting(Profile* profile) {
  host_resolver_->set_profile_for_testing(profile);
}

void HttpsLatencyRoutine::MakeHttpsRequest() {
  std::string hostname = hostnames_to_query_https_.back();
  hostnames_to_query_https_.pop_back();
  request_start_time_ = tick_clock_->NowTicks();
  http_request_manager_->MakeRequest(
      GURL(hostname), ksRequestTimeoutMs,
      base::BindOnce(&HttpsLatencyRoutine::OnHttpsRequestComplete, weak_ptr()));
}

void HttpsLatencyRoutine::OnHttpsRequestComplete(bool connected) {
  request_end_time_ = tick_clock_->NowTicks();
  if (!connected) {
    failed_connection_ = true;
    AnalyzeResultsAndExecuteCallback();
    return;
  }
  const base::TimeDelta latency = request_end_time_ - request_start_time_;
  latencies_.emplace_back(latency);
  if (hostnames_to_query_https_.size() > 0) {
    MakeHttpsRequest();
    return;
  }
  AnalyzeResultsAndExecuteCallback();
}

}  // namespace network_diagnostics
}  // namespace chromeos
