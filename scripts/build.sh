#!/bin/sh
#
#   Builds the addon packages: dist/wireguard-<arch>-<version>.tar.gz and .sha256 for aarch64, x86_64
#   and armv7l (the asset names openccu-lite's catalogue resolves by uname -m).
#
#     VERSION=0.1.0 scripts/build.sh            # all three
#     ARCHES=x86_64 scripts/build.sh            # one
#     SKIP_UI=1 scripts/build.sh                # keep addon/wireguard/app as it is
#
#   The page is built with npm in ui/ and copied to addon/wireguard/app (the daemon serves it at
#   /addons/wireguard/); the manifest's icons, the 503 page and the proxy rule live in addon/wireguard/www
#   and addon/wireguard/etc, tracked, where the catalogue reads the icons from the repository at the
#   release tag; the daemon is a static Go binary (CGO_ENABLED=0) per architecture.
#
set -e
cd "$(dirname "$0")/.."
VERSION=${VERSION:-0.0.0-dev}
ARCHES=${ARCHES:-aarch64 x86_64 armv7l}
GO=${GO:-go}

if [ -z "$SKIP_UI" ]; then
    (cd ui && npm ci --no-audit --no-fund && npm run build)
    rm -rf addon/wireguard/app
    mkdir -p addon/wireguard/app
    cp -a ui/dist/. addon/wireguard/app/
fi
cp -a addon/static/. addon/wireguard/www/
printf 'VERSION_ADDON=%s\n' "$VERSION" > addon/wireguard/versions

mkdir -p dist
for arch in $ARCHES; do
    case $arch in
        aarch64) goarch=arm64; goarm= ;;
        x86_64) goarch=amd64; goarm= ;;
        armv7l) goarch=arm; goarm=7 ;;
        *) echo "unknown architecture $arch" >&2; exit 1 ;;
    esac
    mkdir -p addon/wireguard/bin
    rm -f addon/wireguard/bin/wireguard
    CGO_ENABLED=0 GOOS=linux GOARCH=$goarch GOARM=$goarm $GO build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o addon/wireguard/bin/wireguard ./cmd/wireguard

    out=dist/wireguard-$arch-$VERSION.tar.gz
    stage=$(mktemp -d)
    cp -a addon/update_script addon/openccu-lite.json addon/wireguard "$stage/"
    rm -rf "$stage/wireguard/var"
    find "$stage" \( -name '._*' -o -name '.DS_Store' \) -exec rm -f {} +
    chmod 755 "$stage/update_script" "$stage/wireguard/rc.d" "$stage/wireguard/bin/wireguard"
    test -f "$stage/wireguard/etc/lighttpd.conf"
    COPYFILE_DISABLE=1 tar --owner=root --group=root --sort=name --mtime='2026-01-01 00:00Z' -czf "$out" -C "$stage" .
    rm -rf "$stage"
    (cd dist && sha256sum "$(basename "$out")" > "$(basename "$out").sha256")
    echo "built $out"
done
