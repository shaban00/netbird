# Caddy with the plugins install-server.sh's Caddyfile uses: layer4 (TLS
# passthrough to the reverse proxy), rate limiting, and the CrowdSec bouncer
# with AppSec.
ARG VERSION=2

FROM caddy:${VERSION}-builder AS builder

RUN xcaddy build \
    --with github.com/mholt/caddy-l4 \
    --with github.com/mholt/caddy-ratelimit \
    --with github.com/caddyserver/transform-encoder \
	--with github.com/hslatman/caddy-crowdsec-bouncer/http@main \
	--with github.com/hslatman/caddy-crowdsec-bouncer/appsec@main \
	--with github.com/hslatman/caddy-crowdsec-bouncer/layer4@main

FROM caddy:${VERSION}-alpine

COPY --from=builder /usr/bin/caddy /usr/bin/caddy