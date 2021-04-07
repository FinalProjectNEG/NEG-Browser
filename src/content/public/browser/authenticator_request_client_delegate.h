// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_PUBLIC_BROWSER_AUTHENTICATOR_REQUEST_CLIENT_DELEGATE_H_
#define CONTENT_PUBLIC_BROWSER_AUTHENTICATOR_REQUEST_CLIENT_DELEGATE_H_

#include <string>

#include "base/callback_forward.h"
#include "base/containers/span.h"
#include "base/macros.h"
#include "base/optional.h"
#include "build/build_config.h"
#include "content/common/content_export.h"
#include "device/fido/authenticator_get_assertion_response.h"
#include "device/fido/cable/cable_discovery_data.h"
#include "device/fido/fido_request_handler_base.h"
#include "device/fido/fido_transport_protocol.h"

#if defined(OS_MAC)
#include "device/fido/mac/authenticator_config.h"
#endif

namespace device {
class FidoAuthenticator;
class FidoDiscoveryFactory;
}  // namespace device

namespace url {
class Origin;
}

namespace content {

// Interface that the embedder should implement to provide the //content layer
// with embedder-specific configuration for a single Web Authentication API [1]
// request serviced in a given RenderFrame.
//
// [1]: See https://www.w3.org/TR/webauthn/.
class CONTENT_EXPORT AuthenticatorRequestClientDelegate
    : public device::FidoRequestHandlerBase::Observer {
 public:
  // Failure reasons that might be of interest to the user, so the embedder may
  // decide to inform the user.
  enum class InterestingFailureReason {
    kTimeout,
    kKeyNotRegistered,
    kKeyAlreadyRegistered,
    kSoftPINBlock,
    kHardPINBlock,
    kAuthenticatorRemovedDuringPINEntry,
    kAuthenticatorMissingResidentKeys,
    kAuthenticatorMissingUserVerification,
    kAuthenticatorMissingLargeBlob,
    kNoCommonAlgorithms,
    // kStorageFull indicates that a resident credential could not be created
    // because the authenticator has insufficient storage.
    kStorageFull,
    kUserConsentDenied,
    // kWinUserCancelled means that the user clicked "Cancel" in the native
    // Windows UI.
    kWinUserCancelled,
  };

  AuthenticatorRequestClientDelegate();
  ~AuthenticatorRequestClientDelegate() override;

  // Permits the embedder to override normal relying party ID processing. Is
  // given the untrusted, claimed relying party ID from the WebAuthn call, as
  // well as the origin of the caller, and may return a relying party ID to
  // override normal validation.
  //
  // This is an access-control decision: RP IDs are used to control access to
  // credentials so thought is required before allowing an origin to assert an
  // RP ID. RP ID strings may be stored on authenticators and may later appear
  // in management UI.
  virtual base::Optional<std::string> MaybeGetRelyingPartyIdOverride(
      const std::string& claimed_relying_party_id,
      const url::Origin& caller_origin);

  // SetRelyingPartyId sets the RP ID for this request. This is called after
  // |MaybeGetRelyingPartyIdOverride| is given the opportunity to affect this
  // value. For typical origins, the RP ID is just a domain name, but
  // |MaybeGetRelyingPartyIdOverride| may return other forms of strings.
  virtual void SetRelyingPartyId(const std::string& rp_id);

  // Called when the request fails for the given |reason|.
  //
  // Embedders may return true if they want AuthenticatorImpl to hold off from
  // resolving the WebAuthn request with an error, e.g. because they want the
  // user to dismiss an error dialog first. In this case, embedders *must*
  // eventually invoke the FidoRequestHandlerBase::CancelCallback in order to
  // resolve the request. Returning false causes AuthenticatorImpl to resolve
  // the request with the error right away.
  virtual bool DoesBlockRequestOnFailure(InterestingFailureReason reason);

  // Supplies callbacks that the embedder can invoke to initiate certain
  // actions, namely: cancel the request, start the request over, initiate BLE
  // pairing process, cancel WebAuthN request, and dispatch request to connected
  // authenticators.
  virtual void RegisterActionCallbacks(
      base::OnceClosure cancel_callback,
      base::RepeatingClosure start_over_callback,
      device::FidoRequestHandlerBase::RequestCallback request_callback,
      base::RepeatingClosure bluetooth_adapter_power_on_callback);

  // Returns true if the given relying party ID is permitted to receive
  // individual attestation certificates. This:
  //  a) triggers a signal to the security key that returning individual
  //     attestation certificates is permitted, and
  //  b) skips any permission prompt for attestation.
  virtual bool ShouldPermitIndividualAttestation(
      const std::string& relying_party_id);

  // Invokes |callback| with |true| if the given relying party ID is permitted
  // to receive attestation certificates from the provided FidoAuthenticator.
  // Otherwise invokes |callback| with |false|.
  //
  // If |is_enterprise_attestation| is true then that authenticator has asserted
  // that |relying_party_id| is known to it and the attesation has no
  // expectations of privacy.
  //
  // Since these certificates may uniquely identify the authenticator, the
  // embedder may choose to show a permissions prompt to the user, and only
  // invoke |callback| afterwards. This may hairpin |callback|.
  virtual void ShouldReturnAttestation(
      const std::string& relying_party_id,
      const device::FidoAuthenticator* authenticator,
      bool is_enterprise_attestation,
      base::OnceCallback<void(bool)> callback);

  // SupportsResidentKeys returns true if this implementation of
  // |AuthenticatorRequestClientDelegate| supports resident keys. If false then
  // requests to create or get assertions will be immediately rejected and
  // |SelectAccount| will never be called.
  virtual bool SupportsResidentKeys();

  // SetMightCreateResidentCredential indicates whether activating an
  // authenticator may cause a resident credential to be created. A resident
  // credential may be discovered by someone with physical access to the
  // authenticator and thus has privacy implications.
  void SetMightCreateResidentCredential(bool v) override;

  // ConfigureCable optionally configures Cloud-assisted Bluetooth Low Energy
  // transports. |origin| is the origin of the calling site and
  // |pairings_from_extension| are caBLEv1 pairings that have been provided in
  // an extension to the WebAuthn get() call. If the embedder wishes, it may use
  // this to configure caBLE on the |FidoDiscoveryFactory| for use in this
  // request.
  virtual void ConfigureCable(
      const url::Origin& origin,
      base::span<const device::CableDiscoveryData> pairings_from_extension,
      device::FidoDiscoveryFactory* fido_discovery_factory);

  // SelectAccount is called to allow the embedder to select between one or more
  // accounts. This is triggered when the web page requests an unspecified
  // credential (by passing an empty allow-list). In this case, any accounts
  // will come from the authenticator's storage and the user should confirm the
  // use of any specific account before it is returned. The callback takes the
  // selected account, or else |cancel_callback| can be called.
  //
  // This is only called if |SupportsResidentKeys| returns true.
  virtual void SelectAccount(
      std::vector<device::AuthenticatorGetAssertionResponse> responses,
      base::OnceCallback<void(device::AuthenticatorGetAssertionResponse)>
          callback);

  // Returns whether the WebContents corresponding to |render_frame_host| is the
  // active tab in the focused window. We do not want to allow
  // authenticatorMakeCredential operations to be triggered by background tabs.
  //
  // Note that the default implementation of this function, and the
  // implementation in ChromeContentBrowserClient for Android, return |true| so
  // that testing is possible.
  virtual bool IsFocused();

#if defined(OS_MAC)
  using TouchIdAuthenticatorConfig = device::fido::mac::AuthenticatorConfig;

  // Returns configuration data for the built-in Touch ID platform
  // authenticator. May return nullopt if the authenticator is not available in
  // the current context, in which case the Touch ID authenticator will be
  // unavailable.
  virtual base::Optional<TouchIdAuthenticatorConfig>
  GetTouchIdAuthenticatorConfig();
#endif  // defined(OS_MAC)

  // Returns a bool if the result of the isUserVerifyingPlatformAuthenticator
  // API call should be overridden with that value, or base::nullopt otherwise.
  virtual base::Optional<bool>
  IsUserVerifyingPlatformAuthenticatorAvailableOverride();

  // Saves transport type the user used during WebAuthN API so that the
  // WebAuthN UI will default to the same transport type during next API call.
  virtual void UpdateLastTransportUsed(device::FidoTransportProtocol transport);

  // Disables the UI (needed in cases when called by other components, like
  // cryptotoken).
  virtual void DisableUI();

  virtual bool IsWebAuthnUIEnabled();

  // device::FidoRequestHandlerBase::Observer:
  void OnTransportAvailabilityEnumerated(
      device::FidoRequestHandlerBase::TransportAvailabilityInfo data) override;
  // If true, the request handler will defer dispatch of its request onto the
  // given authenticator to the embedder. The embedder needs to call
  // |StartAuthenticatorRequest| when it wants to initiate request dispatch.
  //
  // This method is invoked before |FidoAuthenticatorAdded|, and may be
  // invoked multiple times for the same authenticator. Depending on the
  // result, the request handler might decide not to make the authenticator
  // available, in which case it never gets passed to
  // |FidoAuthenticatorAdded|.
  bool EmbedderControlsAuthenticatorDispatch(
      const device::FidoAuthenticator& authenticator) override;
  void BluetoothAdapterPowerChanged(bool is_powered_on) override;
  void FidoAuthenticatorAdded(
      const device::FidoAuthenticator& authenticator) override;
  void FidoAuthenticatorRemoved(base::StringPiece device_id) override;
  bool SupportsPIN() const override;
  void CollectPIN(
      base::Optional<int> attempts,
      base::OnceCallback<void(std::string)> provide_pin_cb) override;
  void StartBioEnrollment(base::OnceClosure next_callback) override;
  void OnSampleCollected(int bio_samples_remaining) override;
  void FinishCollectToken() override;
  void OnRetryUserVerification(int attempts) override;
  void OnInternalUserVerificationLocked() override;

 private:
  DISALLOW_COPY_AND_ASSIGN(AuthenticatorRequestClientDelegate);
};

}  // namespace content

#endif  // CONTENT_PUBLIC_BROWSER_AUTHENTICATOR_REQUEST_CLIENT_DELEGATE_H_
