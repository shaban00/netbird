FROM golang:1.26.7-alpine AS builder
WORKDIR /app

RUN echo "netbird:x:1000:1000:netbird:/var/lib/netbird-recorder:/sbin/nologin" > /tmp/passwd && \
    echo "netbird:x:1000:netbird" > /tmp/group && \
    mkdir -p /tmp/var/lib/netbird-recorder

FROM gcr.io/distroless/base:debug
ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/netbird-recorder /go/bin/netbird-recorder
COPY --from=builder /tmp/passwd /etc/passwd
COPY --from=builder /tmp/group /etc/group
COPY --from=builder --chown=1000:1000 /tmp/var/lib/netbird-recorder /var/lib/netbird-recorder
USER netbird:netbird
ENV HOME=/var/lib/netbird-recorder
ENTRYPOINT ["/go/bin/netbird-recorder"]
