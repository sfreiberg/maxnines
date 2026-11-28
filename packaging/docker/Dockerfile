# The MaxNines server, from the binary the release workflow built for each
# architecture, so building the image runs nothing. Distroless has the C and C++
# libraries the server needs and nothing else, not even a shell.
FROM gcr.io/distroless/cc-debian12:nonroot

ARG TARGETARCH
COPY dist/docker/${TARGETARCH}/maxnines-server /usr/bin/maxnines-server
COPY packaging/docker/server.hcl /etc/maxnines/server.hcl
COPY --chown=nonroot:nonroot packaging/docker/data/README.txt /var/lib/maxnines-server/README.txt

VOLUME /var/lib/maxnines-server
WORKDIR /var/lib/maxnines-server
EXPOSE 9000
ENTRYPOINT ["/usr/bin/maxnines-server", "--config", "/etc/maxnines/server.hcl"]
