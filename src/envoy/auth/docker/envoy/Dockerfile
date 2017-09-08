FROM ubuntu:xenial-20160706

ADD envoy etc/auth/envoy
ADD envoy.conf etc/auth/envoy.conf

ENTRYPOINT ["etc/auth/envoy", "-c etc/auth/envoy.conf"]
