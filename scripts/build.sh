#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
frontend_directory="$repository_root/internal/web/frontend"
output_directory="${1:-$repository_root/bin}"
if [[ "$output_directory" != /* ]]; then
    output_directory="$repository_root/$output_directory"
fi

for tool in go pnpm; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "required tool '$tool' was not found in PATH" >&2
        exit 1
    fi
done

(
    cd "$frontend_directory"
    pnpm install --frozen-lockfile
    pnpm build
)

mkdir -p "$output_directory"

(
    cd "$repository_root"
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
        go build -trimpath -ldflags="-s -w" \
        -o "$output_directory/audit-proxy-windows-amd64.exe" ./cmd/audit-proxy

    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
        go build -trimpath -ldflags="-s -w" \
        -o "$output_directory/audit-proxy-linux-amd64" ./cmd/audit-proxy
)

printf 'Built:\n  %s\n  %s\n' \
    "$output_directory/audit-proxy-windows-amd64.exe" \
    "$output_directory/audit-proxy-linux-amd64"
