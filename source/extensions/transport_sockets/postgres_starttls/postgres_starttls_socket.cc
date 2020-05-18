#include <iostream>

#include "extensions/transport_sockets/postgres_starttls/postgres_starttls_socket.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace PostgresStartTls {

using absl::ascii_isdigit;

Network::IoResult PostgresStartTlsSocket::doRead(Buffer::Instance& buffer) {
  ENVOY_LOG(trace, "postgres_starttls: doRead ({}) {}", buffer.length(), buffer.toString());
  Network::IoResult result;

  if (passthrough_) {
    return passthrough_->doRead(buffer);
  }

  Envoy::Buffer::OwnedImpl local_buffer;
  result = raw_socket_->doRead(local_buffer);
  buffer.add(local_buffer);

  ENVOY_LOG(debug, "postgres_starttls: local_buffer {}", local_buffer.toString());

  //absl::StrAppend(&command_buffer_, local_buffer.toString());

  uint32_t code = buffer.peekBEInt<uint32_t>(4);
  // Startup message with 1234 in the most significant 16 bits
  // indicate request to encrypt (SSLRequest).
  if (code >= 0x04d20000) {
    ENVOY_LOG(debug, "postgres_starttls: SSL request sent");

    Envoy::Buffer::OwnedImpl outbuf;
    outbuf.add(absl::string_view("S"));
    raw_socket_->doWrite(outbuf, false);
    
    ssl_socket_->setTransportSocketCallbacks(*callbacks_);
    ssl_socket_->onConnected();

    passthrough_ = std::move(ssl_socket_);
    raw_socket_.reset();
  } else {
    // go to passthrough mode if we see any other unexpected commands, we may
    // need to allow e.g. NOOP/RSET but let's try being strict first
    ENVOY_LOG(trace, "postgres_starttls: passthrough default to raw_socket");
    passthrough_ = std::move(raw_socket_);
    ssl_socket_.reset();
  }

  /*size_t lf = command_buffer_.find('\n');
  if (lf == std::string::npos) {
    return result;
  }

  if (absl::StartsWithIgnoreCase(command_buffer_, "EHLO")) {
    ehlo_ = true;
  } else if (absl::EqualsIgnoreCase(command_buffer_, "STARTTLS\r\n")) {
    Envoy::Buffer::OwnedImpl outbuf;
    outbuf.add(absl::string_view("220 ready for tls\r\n"));
    raw_socket_->doWrite(outbuf, false);

    ssl_socket_->setTransportSocketCallbacks(*callbacks_);
    ssl_socket_->onConnected();
    passthrough_ = std::move(ssl_socket_);
    raw_socket_.reset();
  } else {
    // go to passthrough mode if we see any other unexpected commands, we may
    // need to allow e.g. NOOP/RSET but let's try being strict first
    passthrough_ = std::move(raw_socket_);
    ssl_socket_.reset();
  }*/

  //command_buffer_.clear();

  return result;
}

Network::IoResult PostgresStartTlsSocket::doWrite(Buffer::Instance& buffer, bool end_stream) {
  ENVOY_LOG(trace, "postgres_starttls: doWrite ({}) {}", buffer.length(), buffer.toString());

  if (passthrough_) {
    return passthrough_->doWrite(buffer, end_stream);
  }

  Envoy::Buffer::OwnedImpl local;
  local.move(buffer);
  /*absl::StrAppend(&response_buffer_, local.toString());
  if (!ScanEsmtpResponse(response_buffer_)) {
    return {Network::PostIoAction::KeepOpen, local.length(), false};
  }

  if (ehlo_) {
    AddStarttlsToCapabilities(&response_buffer_);
    ehlo_ = false;
  }

  local = Envoy::Buffer::OwnedImpl(response_buffer_);
  response_buffer_.clear();*/

  Network::IoResult result = raw_socket_->doWrite(local, end_stream);
  result.bytes_processed_ = local.length();
  return result;
}

// TODO: right now this just expects DownstreamTlsContext in
// TransportSocket.typed_config which it passes to both transport sockets. There
// probably needs to be a separate config proto for this that can hold the
// config protos for both RawBuffer/SslSocket.
Network::TransportSocketPtr ServerPostgresStartTlsSocketFactory::createTransportSocket(
    Network::TransportSocketOptionsSharedPtr transport_socket_options) const {
    ENVOY_LOG(trace, "postgres_starttls: createTransportSocket");
    return std::make_unique<PostgresStartTlsSocket>(
        raw_socket_factory_->createTransportSocket(transport_socket_options),
        tls_socket_factory_->createTransportSocket(transport_socket_options),
        transport_socket_options);
}

ServerPostgresStartTlsSocketFactory::~ServerPostgresStartTlsSocketFactory() {}

}  // namespace PostgresStartTls
}  // namespace TransportSockets
}  // namespace Extensions
}  // namespace Envoy
