#pragma once

#include "envoy/registry/registry.h"
#include "envoy/server/transport_socket_config.h"

#include "extensions/transport_sockets/well_known_names.h"

namespace Envoy {
namespace Extensions {
namespace TransportSockets {
namespace PostgresStartTls {

class PostgresStartTlsSocketConfigFactory
    : public virtual Server::Configuration::TransportSocketConfigFactory {
 public:
  ~PostgresStartTlsSocketConfigFactory() override = default;
  std::string name() const override { return TransportSocketNames::get().PostgresStartTls; }
};

class DownstreamPostgresStartTlsSocketFactory
    : public Server::Configuration::DownstreamTransportSocketConfigFactory,
      public PostgresStartTlsSocketConfigFactory {
public:
  Network::TransportSocketFactoryPtr
  createTransportSocketFactory(const Protobuf::Message& config,
                               Server::Configuration::TransportSocketFactoryContext& context,
                               const std::vector<std::string>& server_names) override;
  ProtobufTypes::MessagePtr createEmptyConfigProto() override;
};

DECLARE_FACTORY(DownstreamPostgresStartTlsSocketFactory);


}  // namespace PostgresStartTls
}  // namespace TransportSockets
}  // namespace Extensions
}  // namespace Envoy
