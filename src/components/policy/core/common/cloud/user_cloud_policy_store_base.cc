// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/policy/core/common/cloud/user_cloud_policy_store_base.h"

#include <utility>

#include "base/sequenced_task_runner.h"
#include "components/policy/core/common/cloud/cloud_external_data_manager.h"
#include "components/policy/core/common/cloud/cloud_policy_constants.h"
#include "components/policy/core/common/policy_map.h"
#include "components/policy/core/common/policy_proto_decoders.h"
#include "components/policy/proto/cloud_policy.pb.h"
#include "components/policy/proto/device_management_backend.pb.h"

namespace policy {

UserCloudPolicyStoreBase::UserCloudPolicyStoreBase(
    scoped_refptr<base::SequencedTaskRunner> background_task_runner,
    PolicyScope policy_scope,
    PolicySource policy_source)
    : background_task_runner_(background_task_runner),
      policy_scope_(policy_scope),
      policy_source_(policy_source) {
  DCHECK(policy_source == POLICY_SOURCE_CLOUD ||
         policy_source == POLICY_SOURCE_PRIORITY_CLOUD);
}

UserCloudPolicyStoreBase::~UserCloudPolicyStoreBase() {}

std::unique_ptr<UserCloudPolicyValidator>
UserCloudPolicyStoreBase::CreateValidator(
    std::unique_ptr<enterprise_management::PolicyFetchResponse> policy,
    CloudPolicyValidatorBase::ValidateTimestampOption timestamp_option) {
  // Configure the validator.
  auto validator = std::make_unique<UserCloudPolicyValidator>(
      std::move(policy), background_task_runner_);
  validator->ValidatePolicyType(dm_protocol::kChromeUserPolicyType);
  validator->ValidateAgainstCurrentPolicy(
      policy_.get(), timestamp_option,
      CloudPolicyValidatorBase::DM_TOKEN_REQUIRED,
      CloudPolicyValidatorBase::DEVICE_ID_REQUIRED);
  validator->ValidatePayload();
  return validator;
}

void UserCloudPolicyStoreBase::InstallPolicy(
    std::unique_ptr<enterprise_management::PolicyData> policy_data,
    std::unique_ptr<enterprise_management::CloudPolicySettings> payload,
    const std::string& policy_signature_public_key) {
  // Decode the payload.
  policy_map_.Clear();
  DecodeProtoFields(*payload, external_data_manager(), policy_source_,
                    policy_scope_, &policy_map_);
  policy_ = std::move(policy_data);
  policy_signature_public_key_ = policy_signature_public_key;
}

}  // namespace policy
