FROM scratch
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/edged /
# Because its a scratch image, it does not contain ca-certificates dus it ignores the ssl verification
# you can copy/mount `/etc/ssl/certs/ca-certificates.crt` into this container then enable verify ssl
ENV VERIFY_SSL_UPSTREAM=false \
  VERIFY_SSL_ACME=false
ENTRYPOINT ["/edged"]
