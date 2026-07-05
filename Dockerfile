FROM scratch
COPY edged /
ENTRYPOINT ["/edged"]
