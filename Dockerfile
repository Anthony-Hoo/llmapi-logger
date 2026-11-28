# syntax=docker/dockerfile:1.7

FROM node:24-alpine AS web-build

ARG PNPM_VERSION=10.15.0
RUN npm install --global "pnpm@${PNPM_VERSION}"

WORKDIR /src/internal/web/frontend
COPY internal/web/frontend/package.json \
     internal/web/frontend/pnpm-lock.yaml \
     internal/web/frontend/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

COPY internal/web/frontend/ ./
RUN pnpm build


FROM golang:1.27-alpine AS go-build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY --from=web-build /src/internal/web/dist/ ./internal/web/dist/

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/audit-proxy ./cmd/audit-proxy && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/audit-import ./cmd/audit-import && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/audit-archive ./cmd/audit-archive && \
    mkdir -p /out/rootfs/data /out/rootfs/staging /out/rootfs/etc/audit-proxy


# Agent access Skill packages (doc/features/25-agent-access-contract.md
# section 5): llmaudit cross-compiled for five platforms, one reproducible zip
# per platform and manifest.json. The server serves them from agent-packages
# next to its binary, i.e. /agent-packages in the final image.
FROM go-build AS agent-packages

COPY skill/ ./skill/
RUN go run ./internal/agentdist/cmd/agentpack -skill skill/llmapi-audit -out /out/agent-packages


FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=go-build /out/audit-proxy /audit-proxy
COPY --from=go-build /out/audit-import /audit-import
COPY --from=go-build /out/audit-archive /audit-archive
COPY --from=agent-packages /out/agent-packages /agent-packages
COPY --from=go-build --chown=65532:65532 /out/rootfs/data /data
# audit.staging.dir: the start-up check refuses a directory open to group or
# others, so it is created 0700 for the non-root user. A new named volume
# mounted here copies this owner and mode.
COPY --from=go-build --chown=65532:65532 --chmod=0700 /out/rootfs/staging /staging
COPY --from=go-build --chown=65532:65532 /out/rootfs/etc/audit-proxy /etc/audit-proxy

USER 65532:65532
EXPOSE 8080 8081
ENTRYPOINT ["/audit-proxy"]
CMD ["--config", "/etc/audit-proxy/config.yaml"]
