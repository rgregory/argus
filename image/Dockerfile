# Argus: macOS log + syslog analysis with CrowdSec and threat intel.
# Build from the repository root:  container build -t argus:latest -f image/Dockerfile .
ARG CROWDSEC_IMAGE=docker.io/crowdsecurity/crowdsec:latest
ARG NODE_IMAGE=docker.io/library/node:24-alpine

# ---- app dependencies (pure JS; node:sqlite is built into Node 24)
FROM ${NODE_IMAGE} AS app
WORKDIR /opt/argus/app
COPY app/package.json app/package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund
COPY app/ ./

# ---- runtime: official CrowdSec image (Alpine) + Node + syslog-ng
FROM ${CROWDSEC_IMAGE}
RUN apk add --no-cache bash libstdc++ libgcc syslog-ng tini tzdata ca-certificates
COPY --from=app /usr/local/bin/node /usr/local/bin/node
COPY --from=app /opt/argus/app /opt/argus/app
COPY image/syslog-ng.conf      /etc/argus/syslog-ng.conf
COPY image/acquis-argus.yaml   /etc/argus/acquis-argus.yaml
COPY image/entrypoint.sh       /opt/argus/entrypoint.sh
RUN chmod 0755 /opt/argus/entrypoint.sh \
 && node --version \
 && node -e "require('node:sqlite')" \
 && syslog-ng --syntax-only -f /etc/argus/syslog-ng.conf

ENV ARGUS_STATE=/var/lib/argus \
    ARGUS_DATA=/data \
    ARGUS_INBOX=/host/inbox \
    ARGUS_HOST_ROOT=/host \
    ARGUS_HTTP_PORT=7080 \
    NODE_ENV=production \
    NODE_NO_WARNINGS=1

EXPOSE 7080 5514/udp 5515/tcp
ENTRYPOINT ["/sbin/tini", "-g", "--", "/opt/argus/entrypoint.sh"]
