// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMPONENTS_CAST_CHANNEL_CAST_SOCKET_H_
#define COMPONENTS_CAST_CHANNEL_CAST_SOCKET_H_

#include <stdint.h>

#include <queue>
#include <string>

#include "base/cancelable_callback.h"
#include "base/gtest_prod_util.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/observer_list.h"
#include "base/threading/thread_checker.h"
#include "base/timer/timer.h"
#include "components/cast_channel/cast_auth_util.h"
#include "components/cast_channel/cast_channel_enum.h"
#include "components/cast_channel/cast_transport.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "net/base/completion_once_callback.h"
#include "net/base/io_buffer.h"
#include "net/base/ip_endpoint.h"
#include "net/log/net_log_source.h"
#include "services/network/public/mojom/network_context.mojom.h"
#include "services/network/public/mojom/tls_socket.mojom.h"
#include "third_party/openscreen/src/cast/common/channel/proto/cast_channel.pb.h"

namespace net {
class X509Certificate;
}

namespace cast_channel {

using ::cast::channel::CastMessage;

class Logger;
class MojoDataPump;
struct LastError;

// Cast device capabilities.
enum CastDeviceCapability : int {
  NONE = 0,
  VIDEO_OUT = 1 << 0,
  VIDEO_IN = 1 << 1,
  AUDIO_OUT = 1 << 2,
  AUDIO_IN = 1 << 3,
  DEV_MODE = 1 << 4,
  MULTIZONE_GROUP = 1 << 5
};

// Public interface of the CastSocket class.
class CastSocket {
 public:
  // Invoked when CastSocket opens.
  // |socket|: raw pointer of opened socket (this pointer). Guaranteed to be
  // valid in callback function. Do not pass |socket| around.
  using OnOpenCallback = base::OnceCallback<void(CastSocket* socket)>;

  class Observer {
   public:
    virtual ~Observer() {}

    // Invoked when an error occurs on |socket|.
    virtual void OnError(const CastSocket& socket,
                         ChannelError error_state) = 0;

    // Invoked when |socket| receives a message.
    virtual void OnMessage(const CastSocket& socket,
                           const CastMessage& message) = 0;

    virtual void OnReadyStateChanged(const CastSocket& socket);
  };

  virtual ~CastSocket() {}

  // Used by BrowserContextKeyedAPIFactory.
  static const char* service_name() { return "CastSocketImplManager"; }

  // Connects the channel to the peer. If successful, the channel will be in
  // READY_STATE_OPEN.  DO NOT delete the CastSocket object in |callback|.
  // Instead use Close().
  // |callback| will be invoked with any ChannelError that occurred, or
  // CHANNEL_ERROR_NONE if successful.
  // If the CastSocket is destroyed while the connection is pending, |callback|
  // will be invoked with CHANNEL_ERROR_UNKNOWN. In this case, invoking
  // |callback| must not result in any re-entrancy behavior.
  virtual void Connect(OnOpenCallback callback) = 0;

  // Closes the channel if not already closed. On completion, the channel will
  // be in READY_STATE_CLOSED.
  //
  // It is fine to delete this object in |callback|.
  virtual void Close(net::CompletionOnceCallback callback) = 0;

  // The IP endpoint for the destination of the channel.
  virtual const net::IPEndPoint& ip_endpoint() const = 0;

  // Channel id generated by the CastChannelService.
  virtual int id() const = 0;

  // Sets the channel id generated by CastChannelService.
  virtual void set_id(int id) = 0;

  // The ready state of the channel.
  virtual ReadyState ready_state() const = 0;

  // Returns the last error that occurred on this channel, or
  // CHANNEL_ERROR_NONE if no error has occurred.
  virtual ChannelError error_state() const = 0;

  // True when keep-alive signaling is handled for this socket.
  virtual bool keep_alive() const = 0;

  // Whether the channel is audio only as identified by the device
  // certificate during channel authentication.
  virtual bool audio_only() const = 0;

  // Marks a socket as invalid due to an error, and sends an OnError
  // event to |delegate_|.
  // The OnError event receipient is responsible for closing the socket in the
  // event of an error.
  // Setting the error state does not close the socket if it is open.
  virtual void SetErrorState(ChannelError error_state) = 0;

  // Returns a pointer to the socket's message transport layer. Can be used to
  // send and receive CastMessages over the socket.
  virtual CastTransport* transport() const = 0;

  // Registers |observer| with the socket to receive messages and error events.
  virtual void AddObserver(Observer* observer) = 0;

  // Unregisters |observer|.
  virtual void RemoveObserver(Observer* observer) = 0;
};

// Holds parameters necessary to open a Cast channel (CastSocket) to a Cast
// device.
struct CastSocketOpenParams {
  // IP endpoint of the Cast device.
  net::IPEndPoint ip_endpoint;

  // Connection timeout interval. If this value is not set, Cast socket will not
  // report CONNECT_TIMEOUT error and may hang when connecting to a Cast device.
  base::TimeDelta connect_timeout;

  // Amount of idle time to wait before disconnecting. Cast socket will ping
  // Cast device periodically at |ping_interval| to check liveness. If it does
  // not receive response in |liveness_timeout|, it reports PING_TIMEOUT error.
  // |liveness_timeout| should always be larger than or equal to
  // |ping_interval|.
  // If this value is not set, there is not periodic ping and Cast socket is
  // always assumed alive.
  base::TimeDelta liveness_timeout;

  // Amount of idle time to wait before pinging the Cast device. See comments
  // for |liveness_timeout|.
  base::TimeDelta ping_interval;

  // A bit vector representing the capabilities of the sink. The values are
  // defined in components/cast_channel/cast_socket.h.
  uint64_t device_capabilities;

  CastSocketOpenParams(const net::IPEndPoint& ip_endpoint,
                       base::TimeDelta connect_timeout);
  CastSocketOpenParams(const net::IPEndPoint& ip_endpoint,
                       base::TimeDelta connect_timeout,
                       base::TimeDelta liveness_timeout,
                       base::TimeDelta ping_interval,
                       uint64_t device_capabilities);
};

// This class implements a channel between Chrome and a Cast device using a TCP
// socket with SSL.  The channel may authenticate that the receiver is a genuine
// Cast device.  All CastSocketImpl objects must be used only on the IO thread.
//
// NOTE: Not called "CastChannel" to reduce confusion with the generated API
// code.
class CastSocketImpl : public CastSocket {
 public:
  using NetworkContextGetter =
      base::RepeatingCallback<network::mojom::NetworkContext*()>;
  CastSocketImpl(NetworkContextGetter network_context_getter,
                 const CastSocketOpenParams& open_params,
                 const scoped_refptr<Logger>& logger);

  CastSocketImpl(NetworkContextGetter network_context_getter,
                 const CastSocketOpenParams& open_params,
                 const scoped_refptr<Logger>& logger,
                 const AuthContext& auth_context);

  // Ensures that the socket is closed.
  ~CastSocketImpl() override;

  // CastSocket interface.
  void Connect(OnOpenCallback callback) override;
  CastTransport* transport() const override;
  void Close(net::CompletionOnceCallback callback) override;
  const net::IPEndPoint& ip_endpoint() const override;
  int id() const override;
  void set_id(int channel_id) override;
  ReadyState ready_state() const override;
  ChannelError error_state() const override;
  bool keep_alive() const override;
  bool audio_only() const override;
  void AddObserver(Observer* observer) override;
  void RemoveObserver(Observer* observer) override;

  static net::NetworkTrafficAnnotationTag GetNetworkTrafficAnnotationTag();

 protected:
  // CastTransport::Delegate methods for receiving handshake messages.
  class AuthTransportDelegate : public CastTransport::Delegate {
   public:
    explicit AuthTransportDelegate(CastSocketImpl* socket);

    // Gets the error state of the channel.
    // Returns CHANNEL_ERROR_NONE if no errors are present.
    ChannelError error_state() const;

    // Gets recorded error details.
    LastError last_error() const;

    // CastTransport::Delegate interface.
    void OnError(ChannelError error_state) override;
    void OnMessage(const CastMessage& message) override;
    void Start() override;

   private:
    CastSocketImpl* socket_;
    ChannelError error_state_;
    LastError last_error_;
  };

  // CastTransport::Delegate methods to receive normal messages and errors.
  class CastSocketMessageDelegate : public CastTransport::Delegate {
   public:
    CastSocketMessageDelegate(CastSocketImpl* socket);
    ~CastSocketMessageDelegate() override;

    // CastTransport::Delegate implementation.
    void OnError(ChannelError error_state) override;
    void OnMessage(const CastMessage& message) override;
    void Start() override;

   private:
    CastSocketImpl* const socket_;
    DISALLOW_COPY_AND_ASSIGN(CastSocketMessageDelegate);
  };

  // Replaces the internally-constructed transport object with one provided
  // by the caller (e.g. a mock).
  void SetTransportForTesting(std::unique_ptr<CastTransport> transport);

  void SetPeerCertForTesting(scoped_refptr<net::X509Certificate> peer_cert);

  // Verifies whether the socket complies with cast channel policy.
  // Audio only channel policy mandates that a device declaring a video out
  // capability must not have a certificate with audio only policy.
  bool VerifyChannelPolicy(const AuthResult& result);

  void Connect();

 private:
  FRIEND_TEST_ALL_PREFIXES(MockCastSocketTest, TestObservers);
  friend class AuthTransportDelegate;

  void SetErrorState(ChannelError error_state) override;

  // Frees resources and cancels pending callbacks.  |ready_state_| will be set
  // READY_STATE_CLOSED on completion.  A no-op if |ready_state_| is already
  // READY_STATE_CLOSED.
  void CloseInternal();

  // Verifies whether the challenge reply received from the peer is valid:
  // 1. Signature in the reply is valid.
  // 2. Certificate is rooted to a trusted CA.
  virtual bool VerifyChallengeReply();

  // Invoked by a cancelable closure when connection setup time
  // exceeds the interval specified at |connect_timeout|.
  void OnConnectTimeout();

  /////////////////////////////////////////////////////////////////////////////
  // Following methods work together to implement the following flow:
  // 1. Create a new TCP socket and connect to it
  // 2. Create a new SSL socket and try connecting to it
  // 3. If connection fails due to invalid cert authority, then extract the
  //    peer certificate from the error.
  // 4. Whitelist the peer certificate and try #1 and #2 again.
  // 5. If SSL socket is connected successfully, and if protocol is casts://
  //    then issue an auth challenge request.
  // 6. Validate the auth challenge response.
  //
  // Main method that performs connection state transitions.
  void DoConnectLoop(int result);
  // Each of the below Do* method is executed in the corresponding
  // connection state. For example when connection state is TCP_CONNECT
  // DoTcpConnect is called, and so on.
  int DoTcpConnect();
  int DoTcpConnectComplete(int result);
  int DoSslConnect();
  int DoSslConnectComplete(int result);
  int DoAuthChallengeSend();
  int DoAuthChallengeSendComplete(int result);
  int DoAuthChallengeReplyComplete(int result);

  // Callback from network::mojom::NetworkContext::CreateTCPConnectedSocket.
  void OnConnect(int result,
                 const base::Optional<net::IPEndPoint>& local_addr,
                 const base::Optional<net::IPEndPoint>& peer_addr,
                 mojo::ScopedDataPipeConsumerHandle receive_stream,
                 mojo::ScopedDataPipeProducerHandle send_stream);
  void OnUpgradeToTLS(int result,
                      mojo::ScopedDataPipeConsumerHandle receive_stream,
                      mojo::ScopedDataPipeProducerHandle send_stream,
                      const base::Optional<net::SSLInfo>& ssl_info);
  /////////////////////////////////////////////////////////////////////////////

  // Resets the cancellable callback used for async invocations of
  // DoConnectLoop.
  void ResetConnectLoopCallback();

  // Posts a task to invoke |connect_loop_callback_| with |result| on the
  // current message loop.
  void PostTaskToStartConnectLoop(int result);

  // Runs the external connection callback and resets it.
  void DoConnectCallback();

  virtual base::OneShotTimer* GetTimer();

  void SetConnectState(ConnectionState connect_state);
  void SetReadyState(ReadyState ready_state);

  THREAD_CHECKER(thread_checker_);

  // The id of the channel.
  int channel_id_;

  // Cast socket related settings.
  CastSocketOpenParams open_params_;

  // Shared logging object, used to log CastSocket events for diagnostics.
  scoped_refptr<Logger> logger_;

  NetworkContextGetter network_context_getter_;

  // Owned remote to the underlying TCP socket.
  mojo::Remote<network::mojom::TCPConnectedSocket> tcp_socket_;

  // Owned remote to the underlying SSL socket.
  mojo::Remote<network::mojom::TLSClientSocket> socket_;

  // Helper class to write to the SSL socket.
  std::unique_ptr<MojoDataPump> mojo_data_pump_;

  // Certificate of the peer. This field may be empty if the peer
  // certificate is not yet fetched.
  scoped_refptr<net::X509Certificate> peer_cert_;

  // The challenge context for the current connection.
  const AuthContext auth_context_;

  // Reply received from the receiver to a challenge request.
  std::unique_ptr<CastMessage> challenge_reply_;

  // Callbacks invoked when the socket is connected or fails to connect.
  std::vector<OnOpenCallback> connect_callbacks_;

  // Callback invoked by |connect_timeout_timer_| to cancel the connection.
  base::CancelableOnceClosure connect_timeout_callback_;

  // Timer invoked when the connection has timed out.
  std::unique_ptr<base::OneShotTimer> connect_timeout_timer_;

  // Set when a timeout is triggered and the connection process has
  // canceled.
  bool is_canceled_;

  // Whether the channel is audio only as identified by the device
  // certificate during channel authentication.
  bool audio_only_;

  // Connection flow state machine state.
  ConnectionState connect_state_;

  // Write flow state machine state.
  WriteState write_state_;

  // Read flow state machine state.
  ReadState read_state_;

  // The last error encountered by the channel.
  ChannelError error_state_;

  // The current status of the channel.
  ReadyState ready_state_;

  // Callback which, when invoked, will re-enter the connection state machine.
  // Oustanding callbacks will be cancelled when |this| is destroyed.
  // The callback signature is based on net::CompletionCallback, which passes
  // operation result codes as byte counts in the success case, or as
  // net::Error enum values for error cases.
  base::CancelableCallback<void(int)> connect_loop_callback_;

  // Cast message formatting and parsing layer.
  std::unique_ptr<CastTransport> transport_;

  // Caller's message read and error handling delegate.
  std::unique_ptr<CastTransport::Delegate> delegate_;

  // Raw pointer to the auth handshake delegate. Used to get detailed error
  // information.
  AuthTransportDelegate* auth_delegate_;

  // List of socket observers.
  base::ObserverList<Observer>::Unchecked observers_;

  base::WeakPtrFactory<CastSocketImpl> weak_factory_{this};

  DISALLOW_COPY_AND_ASSIGN(CastSocketImpl);
};
}  // namespace cast_channel

#endif  // COMPONENTS_CAST_CHANNEL_CAST_SOCKET_H_
