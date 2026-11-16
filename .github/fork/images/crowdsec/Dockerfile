# CrowdSec reading Caddy's access log and serving AppSec to Caddy, with the
# country policy install-server.sh writes (mounted as netbird/country-policy).
FROM crowdsecurity/crowdsec:latest

ENV COLLECTIONS="crowdsecurity/linux crowdsecurity/caddy crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-generic-rules"

COPY acquis.d/caddy.yaml /staging/etc/crowdsec/acquis.d/caddy.yaml
COPY acquis.d/appsec.yaml /staging/etc/crowdsec/acquis.d/appsec.yaml