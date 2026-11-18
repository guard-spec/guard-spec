#!/bin/sh
# Downloads the native libraries that the `onnx` build tag needs and checks
# their SHA-256 values. Used by build/gateway.Dockerfile and `make onnx-deps`.
#
#   build/onnx-deps.sh <dest-dir> [os] [arch] [flavor]
#
# <dest-dir>/lib gets:
#   libonnxruntime.{so,dylib}*  ONNX Runtime CPU (MIT), loaded at run time via dlopen,
#                               taken from Microsoft's onnxruntime wheel on PyPI
#                               (the C API library inside it; the Python
#                               bindings are not used)
#   libtokenizers.a             Hugging Face tokenizers (Rust, Apache-2.0) wrapped by
#                               github.com/daulet/tokenizers (MIT), linked statically
#
# os is linux or darwin, arch is amd64 or arm64 (default: this machine).
#
# flavor is cpu (default) or gpu. gpu (linux amd64 only, for the GPU image
# users build from build/gateway-gpu.Dockerfile) takes ONNX Runtime's CUDA 12 build instead:
# libonnxruntime.so with libonnxruntime_providers_cuda.so and
# libonnxruntime_providers_shared.so next to it (ONNX Runtime loads the
# providers from the directory of libonnxruntime.so; TensorRT is left out),
# and VERSION.onnxruntime for `doctor`. The CUDA and cuDNN libraries come
# from the image's nvidia/cuda base, not from here.
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

dest=${1:?usage: onnx-deps.sh <dest-dir> [os] [arch] [cpu|gpu]}
os=${2:-$(uname -s | tr '[:upper:]' '[:lower:]')}
arch=${3:-$(uname -m)}
flavor=${4:-cpu}
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "unsupported arch: $arch" >&2; exit 1 ;;
esac
case "$flavor-$os-$arch" in
  cpu-*|gpu-linux-amd64) ;;
  *) echo "unsupported flavor: $flavor on $os-$arch (gpu is linux amd64 only)" >&2; exit 1 ;;
esac

# ONNX Runtime comes from Microsoft's wheels on PyPI (files.pythonhosted.org):
# the GitHub releases of microsoft/onnxruntime were unreachable (404) on
# 2026-11-18, and the wheels carry the same C API library (libonnxruntime),
# checked to score eval/ identically on darwin-arm64 (2,176 rows, max
# difference 0). The wheel is pinned by SHA-256 like the archive was.
pypi=https://files.pythonhosted.org/packages
case "$os-$arch" in
  linux-amd64)
    ort_url=$pypi/eb/27/c6a823bac55b2977bea2027c3ec9393a2c1002cb9a09eb40354563e02730/onnxruntime-$ORT_VERSION-cp312-cp312-manylinux_2_28_x86_64.whl
    ort_sha=1f3dea47f2f0e5117c2404cea7d21fd253ae7836a3bf167a501cdfbb2600d536
    ort_member=onnxruntime/capi/libonnxruntime.so.$ORT_VERSION
    tok_sha=72556cdca798dd4ea7cdaba308e5f0d68a8cb93b67c96edf485b7a0edd7b07f4 ;;
  linux-arm64)
    ort_url=$pypi/ba/e4/1ed1a7a5f4702d899091fa2b976d377995250c307326ec8dc9ae6378aa13/onnxruntime-$ORT_VERSION-cp312-cp312-manylinux_2_28_aarch64.whl
    ort_sha=0b9a492176886992e0e875f06bc0367e333f5fff11711a2d642e18b02f3009cc
    ort_member=onnxruntime/capi/libonnxruntime.so.$ORT_VERSION
    tok_sha=e96545ad05930c26f51f63d932ee6d3bbd32bbed149e102c5290d587a2293067 ;;
  darwin-arm64)
    ort_url=$pypi/0e/f7/cecc0efeeea83bff2f7789ae1b80f27fa0f0210d6d9d66d1f0031a6b5e47/onnxruntime-$ORT_VERSION-cp312-cp312-macosx_14_0_arm64.whl
    ort_sha=96dd2564b10ea7153ad9c207e7cd8e5917cb3ba521e0e0a62ac03486fdc8d56c
    ort_member=onnxruntime/capi/libonnxruntime.$ORT_VERSION.dylib
    tok_sha=fb84b8b2e349a5952767ffe80ccd862fc44084de47f3b0cc3f0b7c9d4e649cf7 ;;
  *) echo "unsupported platform: $os-$arch" >&2; exit 1 ;;
esac
if [ "$flavor" = gpu ]; then
  # ONNX Runtime GPU, CUDA 12 build (cuDNN 9), for build/gateway-gpu.Dockerfile:
  # the onnxruntime-gpu wheel.
  ort_url=$pypi/22/97/9531b4d9e566cf2a0f04b4b5c26a3bc0ef2e2e0b6bc943a02c0eead98cf7/onnxruntime_gpu-$ORT_VERSION-cp312-cp312-manylinux_2_28_x86_64.whl
  ort_sha=05d548956197b9d01f59b625de740e0d6be3593f874e241a12dc0362650ecdf7
fi

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

# unzip_member <zip> <member> <out>: a wheel is a zip file. unzip, python3 or
# go, whichever the machine has (the golang builder image has only go).
unzip_member() {
  if command -v unzip >/dev/null 2>&1; then
    unzip -p "$1" "$2" > "$3"
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import sys,zipfile; open(sys.argv[3],"wb").write(zipfile.ZipFile(sys.argv[1]).read(sys.argv[2]))' "$1" "$2" "$3"
  elif command -v go >/dev/null 2>&1; then
    mkdir -p "$tmp/unzip"
    cat > "$tmp/unzip/main.go" <<'GO'
package main

import (
	"archive/zip"
	"io"
	"os"
)

func main() {
	r, err := zip.OpenReader(os.Args[1])
	if err != nil {
		panic(err)
	}
	f, err := r.Open(os.Args[2])
	if err != nil {
		panic(err)
	}
	out, err := os.Create(os.Args[3])
	if err != nil {
		panic(err)
	}
	if _, err := io.Copy(out, f); err != nil {
		panic(err)
	}
	if err := out.Close(); err != nil {
		panic(err)
	}
}
GO
    (cd "$tmp/unzip" && go run main.go "$1" "$2" "$3")
  else
    echo "onnx-deps.sh needs unzip, python3 or go to read the wheel" >&2; exit 1
  fi
  [ -s "$3" ] || { echo "$2 not found in ${1##*/}" >&2; exit 1; }
}

fetch "$ort_url" "$ort_sha" "$tmp/${ort_url##*/}"
whl=$tmp/${ort_url##*/}
# Only the runtime, as one file: it is dlopen()ed by path, so the versioned
# symlinks, the Python bindings and the TensorRT provider are not needed.
case "$os" in
  darwin) ort_lib=libonnxruntime.dylib ;;
  *)      ort_lib=libonnxruntime.so ;;
esac
unzip_member "$whl" "$ort_member" "$dest/lib/$ort_lib"
unzip_member "$whl" onnxruntime/LICENSE "$dest/LICENSE.onnxruntime"
if [ "$flavor" = gpu ]; then
  for p in libonnxruntime_providers_cuda.so libonnxruntime_providers_shared.so; do
    unzip_member "$whl" "onnxruntime/capi/$p" "$dest/lib/$p"
  done
  unzip_member "$whl" onnxruntime/ThirdPartyNotices.txt "$dest/ThirdPartyNotices.onnxruntime.txt"
  echo "$ORT_VERSION (gpu_cuda12)" > "$dest/lib/VERSION.onnxruntime"
fi

fetch "https://github.com/daulet/tokenizers/releases/download/v$TOKENIZERS_VERSION/libtokenizers.$os-$arch.tar.gz" "$tok_sha" "$tmp/tok.tgz"
tar -xzf "$tmp/tok.tgz" -C "$dest/lib" libtokenizers.a

echo "onnx deps ($os-$arch, ORT $ORT_VERSION $flavor, tokenizers $TOKENIZERS_VERSION) in $dest/lib:"
ls -l "$dest/lib"
