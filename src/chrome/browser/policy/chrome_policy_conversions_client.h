// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_POLICY_CHROME_POLICY_CONVERSIONS_CLIENT_H_
#define CHROME_BROWSER_POLICY_CHROME_POLICY_CONVERSIONS_CLIENT_H_

#include "components/policy/core/browser/policy_conversions_client.h"

namespace content {
class BrowserContext;
}

class Profile;

namespace policy {

// ChromePolicyConversionsClient provides an implementation of the
// PolicyConversionsClient interface that is based on Profile and is suitable
// for use in //chrome.
class ChromePolicyConversionsClient : public PolicyConversionsClient {
 public:
  // Creates a ChromePolicyConversionsClient which retrieves Profile-specific
  // policy information from the given |context|.
  explicit ChromePolicyConversionsClient(content::BrowserContext* context);

  ChromePolicyConversionsClient(const ChromePolicyConversionsClient&) = delete;
  ChromePolicyConversionsClient& operator=(
      const ChromePolicyConversionsClient&) = delete;
  ~ChromePolicyConversionsClient() override;

  // PolicyConversionsClient.
  PolicyService* GetPolicyService() const override;
  SchemaRegistry* GetPolicySchemaRegistry() const override;
  const ConfigurationPolicyHandlerList* GetHandlerList() const override;
  bool HasUserPolicies() const override;
  base::Value GetExtensionPolicies(PolicyDomain policy_domain) override;
#if defined(OS_CHROMEOS)
  base::Value GetDeviceLocalAccountPolicies() override;
  base::Value GetIdentityFields() override;
#endif

 private:
  Profile* profile_;
};

}  // namespace policy

#endif  // CHROME_BROWSER_POLICY_CHROME_POLICY_CONVERSIONS_CLIENT_H_
