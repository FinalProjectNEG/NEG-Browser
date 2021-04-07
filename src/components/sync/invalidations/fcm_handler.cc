// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/sync/invalidations/fcm_handler.h"

#include <map>
#include <utility>

#include "base/bind_helpers.h"
#include "base/logging.h"
#include "base/time/time.h"
#include "components/gcm_driver/gcm_driver.h"
#include "components/gcm_driver/instance_id/instance_id_driver.h"
#include "components/sync/invalidations/fcm_registration_token_observer.h"
#include "components/sync/invalidations/invalidations_listener.h"
#include "components/sync/invalidations/switches.h"

namespace syncer {

const char kPayloadKey[] = "payload";

// Lower bound time between two token validations when listening.
const int kTokenValidationPeriodMinutesDefault = 60 * 24;

FCMHandler::FCMHandler(gcm::GCMDriver* gcm_driver,
                       instance_id::InstanceIDDriver* instance_id_driver,
                       const std::string& sender_id,
                       const std::string& app_id)
    : gcm_driver_(gcm_driver),
      instance_id_driver_(instance_id_driver),
      sender_id_(sender_id),
      app_id_(app_id) {}

FCMHandler::~FCMHandler() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  StopListening();
}

void FCMHandler::StartListening() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(!IsListening());
  DCHECK(base::FeatureList::IsEnabled(switches::kUseSyncInvalidations));
  gcm_driver_->AddAppHandler(app_id_, this);
  StartTokenFetch(base::BindOnce(&FCMHandler::DidRetrieveToken,
                                 weak_ptr_factory_.GetWeakPtr()));
}

void FCMHandler::StopListening() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (IsListening()) {
    gcm_driver_->RemoveAppHandler(app_id_);
    token_validation_timer_.AbandonAndStop();
  }
}

void FCMHandler::StopListeningPermanently() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (instance_id_driver_->ExistsInstanceID(app_id_)) {
    instance_id_driver_->GetInstanceID(app_id_)->DeleteID(
        /*callback=*/base::DoNothing());
  }
  StopListening();
}

const std::string& FCMHandler::GetFCMRegistrationToken() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return fcm_registration_token_;
}

void FCMHandler::ShutdownHandler() {
  // Shutdown() should come before and it removes us from the list of app
  // handlers of gcm::GCMDriver so this shouldn't ever been called.
  NOTREACHED();
}

void FCMHandler::AddListener(InvalidationsListener* listener) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  listeners_.AddObserver(listener);
}

void FCMHandler::RemoveListener(InvalidationsListener* listener) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  listeners_.RemoveObserver(listener);
}

void FCMHandler::OnStoreReset() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  // The FCM registration token is not stored by FCMHandler.
}

void FCMHandler::AddTokenObserver(FCMRegistrationTokenObserver* observer) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  token_observers_.AddObserver(observer);
}

void FCMHandler::RemoveTokenObserver(FCMRegistrationTokenObserver* observer) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  token_observers_.RemoveObserver(observer);
}

void FCMHandler::OnMessage(const std::string& app_id,
                           const gcm::IncomingMessage& message) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK_EQ(app_id, app_id_);
  DCHECK(base::FeatureList::IsEnabled(switches::kUseSyncInvalidations));

  auto it = message.data.find(kPayloadKey);
  std::string payload;
  if (it != message.data.end()) {
    payload = it->second;
  }

  for (InvalidationsListener& listener : listeners_) {
    listener.OnInvalidationReceived(payload);
  }
}

void FCMHandler::OnMessagesDeleted(const std::string& app_id) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK_EQ(app_id, app_id_);
}

void FCMHandler::OnSendError(const std::string& app_id,
                             const gcm::GCMClient::SendErrorDetails& details) {
  // Should never be called because the invalidation service doesn't send GCM
  // messages to the server.
  NOTREACHED() << "FCMHandler doesn't send GCM messages.";
}

void FCMHandler::OnSendAcknowledged(const std::string& app_id,
                                    const std::string& message_id) {
  // Should never be called because the invalidation service doesn't send GCM
  // messages to the server.
  NOTREACHED() << "FCMHandler doesn't send GCM messages.";
}

bool FCMHandler::IsListening() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return gcm_driver_->GetAppHandler(app_id_) != nullptr;
}

void FCMHandler::DidRetrieveToken(const std::string& subscription_token,
                                  instance_id::InstanceID::Result result) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!IsListening()) {
    // After we requested the token, |StopListening| has been called. Thus,
    // ignore the token.
    return;
  }

  // TODO(crbug.com/1108783): add a UMA histogram to monitor results.
  // Notify observers only if the token has changed.
  if (result == instance_id::InstanceID::SUCCESS &&
      fcm_registration_token_ != subscription_token) {
    fcm_registration_token_ = subscription_token;
    for (FCMRegistrationTokenObserver& token_observer : token_observers_) {
      token_observer.OnFCMRegistrationTokenChanged();
    }
  } else if (result != instance_id::InstanceID::SUCCESS) {
    DLOG(WARNING) << "Messaging subscription failed: " << result;
  }

  ScheduleNextTokenValidation();
}

void FCMHandler::ScheduleNextTokenValidation() {
  DCHECK(IsListening());

  token_validation_timer_.Start(
      FROM_HERE,
      base::TimeDelta::FromMinutes(kTokenValidationPeriodMinutesDefault),
      base::BindOnce(&FCMHandler::StartTokenValidation,
                     weak_ptr_factory_.GetWeakPtr()));
}

void FCMHandler::StartTokenValidation() {
  DCHECK(IsListening());
  StartTokenFetch(base::BindOnce(&FCMHandler::DidReceiveTokenForValidation,
                                 weak_ptr_factory_.GetWeakPtr()));
}

void FCMHandler::DidReceiveTokenForValidation(
    const std::string& new_token,
    instance_id::InstanceID::Result result) {
  if (!IsListening()) {
    // After we requested the token, |StopListening| has been called. Thus,
    // ignore the token.
    return;
  }

  // Notify observers only if the token has changed.
  if (result == instance_id::InstanceID::SUCCESS &&
      fcm_registration_token_ != new_token) {
    fcm_registration_token_ = new_token;
    for (FCMRegistrationTokenObserver& token_observer : token_observers_) {
      token_observer.OnFCMRegistrationTokenChanged();
    }
  }

  ScheduleNextTokenValidation();
}

void FCMHandler::StartTokenFetch(
    instance_id::InstanceID::GetTokenCallback callback) {
  // TODO(crbug.com/1108780): set appropriate TTL.
  instance_id_driver_->GetInstanceID(app_id_)->GetToken(
      sender_id_, instance_id::kGCMScope,
      /*time_to_live=*/base::TimeDelta(),
      /*options=*/std::map<std::string, std::string>(),
      /*flags=*/{instance_id::InstanceID::Flags::kIsLazy}, std::move(callback));
}

}  // namespace syncer
