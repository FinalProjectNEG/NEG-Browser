// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEVICE_FIDO_AUTHENTICATOR_SELECTION_CRITERIA_H_
#define DEVICE_FIDO_AUTHENTICATOR_SELECTION_CRITERIA_H_

#include "base/component_export.h"
#include "device/fido/fido_constants.h"
#include "device/fido/fido_types.h"

namespace device {

// Represents authenticator properties the relying party can specify to restrict
// the type of authenticator used in creating credentials.
//
// https://w3c.github.io/webauthn/#authenticatorSelection
class COMPONENT_EXPORT(DEVICE_FIDO) AuthenticatorSelectionCriteria {
 public:
  AuthenticatorSelectionCriteria();
  AuthenticatorSelectionCriteria(
      AuthenticatorAttachment authenticator_attachment,
      ResidentKeyRequirement resident_key,
      UserVerificationRequirement user_verification_requirement);
  AuthenticatorSelectionCriteria(const AuthenticatorSelectionCriteria& other);
  AuthenticatorSelectionCriteria(AuthenticatorSelectionCriteria&& other);
  AuthenticatorSelectionCriteria& operator=(
      const AuthenticatorSelectionCriteria& other);
  AuthenticatorSelectionCriteria& operator=(
      AuthenticatorSelectionCriteria&& other);
  bool operator==(const AuthenticatorSelectionCriteria& other) const;
  ~AuthenticatorSelectionCriteria();

  AuthenticatorAttachment authenticator_attachment() const {
    return authenticator_attachment_;
  }

  ResidentKeyRequirement resident_key() const { return resident_key_; }

  UserVerificationRequirement user_verification_requirement() const {
    return user_verification_requirement_;
  }

  void SetAuthenticatorAttachmentForTesting(
      AuthenticatorAttachment attachment) {
    authenticator_attachment_ = attachment;
  }
  void SetResidentKeyForTesting(ResidentKeyRequirement resident_key) {
    resident_key_ = resident_key;
  }
  void SetUserVerificationRequirementForTesting(
      UserVerificationRequirement uv) {
    user_verification_requirement_ = uv;
  }

 private:
  AuthenticatorAttachment authenticator_attachment_ =
      AuthenticatorAttachment::kAny;
  ResidentKeyRequirement resident_key_ = ResidentKeyRequirement::kDiscouraged;
  UserVerificationRequirement user_verification_requirement_ =
      UserVerificationRequirement::kPreferred;
};

}  // namespace device

#endif  // DEVICE_FIDO_AUTHENTICATOR_SELECTION_CRITERIA_H_
