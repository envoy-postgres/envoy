licenses(["notice"])  # Apache 2

load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_package",
)

envoy_package()

envoy_cc_extension(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    #    compatible_with = ["//buildenv/target:gce"],
    security_posture = "robust_to_untrusted_downstream_and_upstream",
    deps = [
        ":postgres_starttls_socket_lib",
        "//include/envoy/network:transport_socket_interface",
        "//include/envoy/registry",
        "//include/envoy/server:transport_socket_config_interface",
        "//source/common/config:utility_lib",
        "//source/extensions/transport_sockets:well_known_names",
        "@envoy_api//envoy/extensions/transport_sockets/tls/v3:pkg_cc_proto",
    ],
)

envoy_cc_library(
    name = "postgres_starttls_socket_lib",
    srcs = ["postgres_starttls_socket.cc"],
    hdrs = ["postgres_starttls_socket.h"],
    #    compatible_with = ["//buildenv/target:gce"],
    external_deps = [
        "abseil_optional",
        "abseil_synchronization",
        "ssl",
    ],
    deps = [
        # ":context_config_lib",
        # ":context_lib",
        # ":utility_lib",
        "//source/common/buffer:buffer_lib",
        "//include/envoy/network:connection_interface",
        "//include/envoy/network:transport_socket_interface",
        "//include/envoy/stats:stats_macros",
        "//source/common/common:assert_lib",
        "//source/common/common:empty_string",
        "//source/common/common:minimal_logger_lib",
        "//source/common/common:thread_annotations",
        #        "//source/extensions/transport_sockets/tls:ssl_socket_lib",
        #        "//source/common/network:raw_buffer_socket_lib",
    ],
)
