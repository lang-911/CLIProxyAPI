#!/bin/sh
set -e
set -u

to_go_os() {
  case "$(uname -s)" in
    Darwin) echo "darwin" ;;
    Linux) echo "linux" ;;
    MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
    *) echo "unsupported" ;;
  esac
}

to_go_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) echo "unsupported" ;;
  esac
}

FORCE_LINUX=0
VERSION="${VERSION:-}"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --linux)
      FORCE_LINUX=1
      ;;
    -h|--help)
      echo "Usage: ./build.sh <version> [--linux]"
      echo "  <version>: release version embedded in the binary name and ldflags"
      echo "  Default: build for current OS/arch"
      echo "  --linux: force Linux build for current arch"
      exit 0
      ;;
    -*)
      echo "Unknown option: $1"
      echo "Usage: ./build.sh <version> [--linux]"
      exit 1
      ;;
    *)
      if [ -n "${VERSION}" ]; then
        echo "Unexpected argument: $1"
        echo "Usage: ./build.sh <version> [--linux]"
        exit 1
      fi
      VERSION="$1"
      ;;
  esac
  shift
done

if [ -z "${VERSION}" ]; then
  echo "VERSION argument is required"
  echo "Usage: ./build.sh <version> [--linux]"
  exit 1
fi

HOST_OS="$(to_go_os)"
HOST_ARCH="$(to_go_arch)"

if [ "${HOST_OS}" = "unsupported" ] || [ "${HOST_ARCH}" = "unsupported" ]; then
  echo "Unsupported host platform: $(uname -s)/$(uname -m)"
  exit 1
fi

TARGET_OS="${TARGET_OS:-${HOST_OS}}"
TARGET_ARCH="${TARGET_ARCH:-${HOST_ARCH}}"

if [ "${FORCE_LINUX}" -eq 1 ]; then
  TARGET_OS="linux"
fi

OUTPUT_NAME="cli-proxy-api_${VERSION}_${TARGET_OS}_${TARGET_ARCH}"

CGO_ENABLED=0 GOOS="${TARGET_OS}" GOARCH="${TARGET_ARCH}" go build -ldflags "-s -w \
  -X 'main.Version=${VERSION}' \
  -X 'main.Commit=$(git rev-parse --short HEAD)' \
  -X 'main.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)'" \
  -o "${OUTPUT_NAME}" ./cmd/server/
