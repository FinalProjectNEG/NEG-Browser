// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <utility>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/location.h"
#include "base/run_loop.h"
#include "base/threading/sequenced_task_runner_handle.h"
#include "components/arc/test/fake_policy_instance.h"

namespace arc {

FakePolicyInstance::FakePolicyInstance() = default;

FakePolicyInstance::~FakePolicyInstance() = default;

void FakePolicyInstance::InitDeprecated(
    mojo::PendingRemote<mojom::PolicyHost> host_remote) {
  Init(std::move(host_remote), base::DoNothing());
}

void FakePolicyInstance::Init(
    mojo::PendingRemote<mojom::PolicyHost> host_remote,
    InitCallback callback) {
  host_remote_.reset();
  host_remote_.Bind(std::move(host_remote));
  std::move(callback).Run();
}

void FakePolicyInstance::OnPolicyUpdated() {}

void FakePolicyInstance::OnCommandReceived(const std::string& command,
                                           OnCommandReceivedCallback callback) {
  command_payload_ = command;
  base::SequencedTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      base::BindOnce(std::move(callback), mojom::CommandResultType::SUCCESS));
}

void FakePolicyInstance::CallGetPolicies(
    mojom::PolicyHost::GetPoliciesCallback callback) {
  host_remote_->GetPolicies(std::move(callback));
  base::RunLoop().RunUntilIdle();
}

}  // namespace arc
