#include "extensions/transport_sockets/postgres_starttls/config.h"
#include "common/config/utility.h"
#include "extensions/transport_sockets/postgres_starttls/postgres_starttls_socket.h"

#include "envoy/extensions/transport_sockets/tls/v3/cert.pb.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace PostgresStartTls {

Network::TransportSocketFactoryPtr
DownstreamPostgresStartTlsSocketFactory::createTransportSocketFactory(
    const Protobuf::Message& message,
    Server::Configuration::TransportSocketFactoryContext& context,
    const std::vector<std::string>& server_names) {

  auto& raw_socket_config_factory =
  Config::Utility::getAndCheckFactoryByName<
      Server::Configuration::DownstreamTransportSocketConfigFactory>("raw_buffer");

  Network::TransportSocketFactoryPtr raw_socket_factory =
      raw_socket_config_factory.createTransportSocketFactory(
          message /* *wrapped_socket_config_proto_for_factory */, context, server_names);

  auto& tls_socket_config_factory =
      Config::Utility::getAndCheckFactoryByName<
          Server::Configuration::DownstreamTransportSocketConfigFactory>("tls");

  Network::TransportSocketFactoryPtr tls_socket_factory =
      tls_socket_config_factory.createTransportSocketFactory(
          message /* *wrapped_socket_config_proto_for_factory */, context, server_names);


  return std::make_unique<ServerPostgresStartTlsSocketFactory>(
      server_names,
      std::move(raw_socket_factory),
      std::move(tls_socket_factory));
}

ProtobufTypes::MessagePtr DownstreamPostgresStartTlsSocketFactory::createEmptyConfigProto() {
  return std::make_unique<envoy::extensions::transport_sockets::tls::v3::DownstreamTlsContext>();
}

REGISTER_FACTORY(DownstreamPostgresStartTlsSocketFactory,
                 Server::Configuration::DownstreamTransportSocketConfigFactory){"postgres_starttls"};

}  // namespace PostgresStartTls
}  // namespace TransportSockets
}  // namespace Extensions
}  // namespace Envoy
