#!/bin/sh
# Downloads the native libraries that the `onnx` build tag needs and checks
# their SHA-256 values. Used by build/gateway.Dockerfile and `make onnx-deps`.
#
#   build/onnx-deps.sh <dest-dir> [os] [arch]
#
# <dest-dir>/lib gets:
#   libonnxruntime.{so,dylib}*  ONNX Runtime CPU (MIT), loaded at run time via dlopen
#   libtokenizers.a             Hugging Face tokenizers (Rust, Apache-2.0) wrapped by
#                               github.com/daulet/tokenizers (MIT), linked statically
#
# os is linux or darwin, arch is amd64 or arm64 (default: this machine).
#
# ONNX_DEPS_CACHE=<dir> (CI only: a directory restored by actions/cache, or
# mounted into the gateway image build): an archive there named
# <sha256>-<file name> is used instead of the download when its SHA-256
# matches the pin below; otherwise it is downloaded and checked as usual, and
# put there when the directory is writable. Unset (releases), nothing changes.
# Same logic as scripts/fetch-verified.sh, kept here because the Dockerfile
# copies only this file.
set -eu

ORT_VERSION=1.31.1
TOKENIZERS_VERSION=1.27.0

dest=${1:?usage: onnx-deps.sh <dest-dir> [os] [arch]}
os=${2:-$(uname -s | tr '[:upper:]' '[:lower:]')}
arch=${3:-$(uname -m)}
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "unsupported arch: $arch" >&2; exit 1 ;;
esac

case "$os-$arch" in
  linux-amd64)
    ort_pkg=onnxruntime-linux-x64-$ORT_VERSION
    ort_sha=c849e36a1ef3e22d4ff217b9d1ce4a3cf5b9467b975610913ae959ad5b16bdc9
    tok_sha=72556cdca798dd4ea7cdaba308e5f0d68a8cb93b67c96edf485b7a0edd7b07f4 ;;
  linux-arm64)
    ort_pkg=onnxruntime-linux-aarch64-$ORT_VERSION
    ort_sha=5317505e2da99be65f8e2775ba3c2afd6d2961fd78aba1bd8f56159f48820c78
    tok_sha=e96545ad05930c26f51f63d932ee6d3bbd32bbed149e102c5290d587a2293067 ;;
  darwin-arm64)
    ort_pkg=onnxruntime-osx-arm64-$ORT_VERSION
    ort_sha=2e1344a1926ee50eb25b38153cb6992c3567515aef0e677a1a520a1798896d6f
    tok_sha=fb84b8b2e349a5952767ffe80ccd862fc44084de47f3b0cc3f0b7c9d4e649cf7 ;;
  *) echo "unsupported platform: $os-$arch" >&2; exit 1 ;;
esac

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

fetch() { # url sha256 out
  if [ -n "${ONNX_DEPS_CACHE:-}" ]; then
    cached=$ONNX_DEPS_CACHE/$2-${1##*/}
    if [ -f "$cached" ]; then
      cp "$cached" "$3"
      if [ "$(sha256 "$3")" = "$2" ]; then
        echo "${1##*/} from $ONNX_DEPS_CACHE, sha256 ok"
        return 0
      fi
      echo "ignoring $cached: sha256 mismatch" >&2
      rm -f "$3"
    fi
  fi
  # A release download hit four 504s in 7 s (v0.1.0-rc.3): retry for longer.
  curl -fsSL --retry 6 --retry-delay 10 --retry-max-time 300 -o "$3" "$1"
  got=$(sha256 "$3")
  if [ "$got" != "$2" ]; then
    echo "sha256 mismatch for $1: got $got, want $2" >&2
    rm -f "$3"; exit 1
  fi
  # Best effort: the cache is a read-only mount inside docker builds.
  if [ -n "${ONNX_DEPS_CACHE:-}" ]; then
    { mkdir -p "$ONNX_DEPS_CACHE" && cp "$3" "$ONNX_DEPS_CACHE/$2-${1##*/}"; } 2>/dev/null || true
  fi
}

mkdir -p "$dest/lib"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fetch "https://github.com/microsoft/onnxruntime/releases/download/v$ORT_VERSION/$ort_pkg.tgz" "$ort_sha" "$tmp/ort.tgz"
tar -xzf "$tmp/ort.tgz" -C "$tmp"
# Only the CPU runtime, as one dereferenced file: it is dlopen()ed by path, so
# the versioned symlinks and the CUDA/TensorRT provider bridge are not needed.
case "$os" in
  darwin) ort_lib=libonnxruntime.dylib ;;
  *)      ort_lib=libonnxruntime.so ;;
esac
cp -L "$tmp/$ort_pkg/lib/$ort_lib" "$dest/lib/$ort_lib"
cp "$tmp/$ort_pkg/LICENSE" "$dest/LICENSE.onnxruntime"

fetch "https://github.com/daulet/tokenizers/releases/download/v$TOKENIZERS_VERSION/libtokenizers.$os-$arch.tar.gz" "$tok_sha" "$tmp/tok.tgz"
tar -xzf "$tmp/tok.tgz" -C "$dest/lib" libtokenizers.a

echo "onnx deps ($os-$arch, ORT $ORT_VERSION, tokenizers $TOKENIZERS_VERSION) in $dest/lib:"
ls -l "$dest/lib"
