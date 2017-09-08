load("@bazel_tools//tools/build_defs/pkg:pkg.bzl", "pkg_tar")
load("@io_bazel_rules_docker//docker:docker.bzl", "docker_build")
#load("@protobuf_bzl//protobuf.bzl")


pkg_tar(
    name = "jwt_proxy_tar",
    extension = "tar.gz",
    files = [
        "//src/envoy/auth:envoy",
    ],
    mode = "0755",
    package_dir = "/usr/local/bin/",
    tags = ["manual"],
)

docker_build(
    name = "jwt_proxy",
    base = "@docker_ubuntu//:xenial",
    entrypoint = [
        "/usr/local/bin/envoy",
    ],
    cmd = [
        "-c src/envoy/auth/sample/envoy.conf",
    ],
#    files = [
#
#    ],
    tars = [
        ":jwt_proxy_tar",
    ],
    ports = [
        "9090",
    ],
)