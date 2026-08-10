# syntax=docker/dockerfile:1.7

FROM node:22-alpine AS web-build

ARG PNPM_VERSION=10.15.0
RUN npm install --global "pnpm@${PNPM_VERSION}"

WORKDIR /src/internal/web/frontend
COPY internal/web/frontend/package.json \
     internal/web/frontend/pnpm-lock.yaml \
     internal/web/frontend/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

COPY internal/web/frontend/ ./
RUN pnpm build


FROM golang:1.25-alpine AS go-build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY --from=web-build /src/internal/web/dist/ ./internal/web/dist/

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/audit-proxy ./cmd/audit-proxy && \
    mkdir -p /out/rootfs/data /out/rootfs/etc/audit-proxy


FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=go-build /out/audit-proxy /audit-proxy
COPY --from=go-build --chown=65532:65532 /out/rootfs/data /data
COPY --from=go-build --chown=65532:65532 /out/rootfs/etc/audit-proxy /etc/audit-proxy

USER 65532:65532
EXPOSE 8080 8081
ENTRYPOINT ["/audit-proxy"]
CMD ["--config", "/etc/audit-proxy/config.yaml"]
