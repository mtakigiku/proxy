

cc_library(
    name = "filter_lib",
    srcs = [
        "test_filter.cc",
    ],
    deps = [
#        ":string_map_proto",
#        "//external:mixer_client_lib",
        "@envoy//source/exe:envoy_common_lib",
    ],
    alwayslink = 1,
)

cc_binary(
    name = "envoy",
    linkopts = ["-lrt"],
    linkstatic = 1,
    visibility = [":__subpackages__"],
    deps = [
        ":filter_lib",
        "@envoy//source/exe:envoy_main_lib",
    ],
)
