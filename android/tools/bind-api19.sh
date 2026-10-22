#!/usr/bin/env bash
# API 19 (Android 4.4, KitKat) bind profile — the additive legacy tier.
#
# Produces mobileapi.aar + libbox.aar bound with -androidapi 19 into
# $LEGPLAT/ws5-api19/aar19/, from which tools/build-manual.sh builds
# the API 19 APK variant:
#
#   sed 's/android:minSdkVersion="21"/android:minSdkVersion="19"/' \
#     app/src/main/AndroidManifest.xml > $LEGPLAT/ws5-api19/AndroidManifest-api19.xml
#   LEGPLAT=$LEGPLAT AAR_DIR=$LEGPLAT/ws5-api19/aar19 MIN_SDK=19 \
#   MANIFEST=$LEGPLAT/ws5-api19/AndroidManifest-api19.xml \
#   ABIS="armeabi-v7a x86" WORK=$LEGPLAT/build-manual19 \
#   OUT=$LEGPLAT/apk19 bash tools/build-manual.sh
# (the manifest copy is needed because aapt2 --min-sdk-version does
# not override a uses-sdk already present in the manifest.)
#
# Why this is a separate profile and not a flag flip (all measured,
# see reports/LEGACY-FULL-5-ANDROID.md):
#
#   * gomobile itself accepts -androidapi down to 16
#     (cmd/gomobile/bind_androidapp.go: minAndroidAPI = 16 in both
#     golang.org/x/mobile and the sagernet fork v0.1.8), but the NDK
#     decides what can actually be targeted: NDK r27/r26 declare
#     meta/platforms.json "min": 21 and gomobile refuses API 19 with
#     "unsupported API version 19 (not in 21..35)". NDK r25c is the
#     last NDK whose floor is 19 ("min": 19), so this profile pins
#     r25c, sha1-verified against Google's repository2-1.xml.
#   * 64-bit ABIs do not exist below API 21 (the r25c sysroot has no
#     aarch64/x86_64 stub directory for 19), so the tier is 32-bit
#     only: -target android/arm,android/386 for both binds.
#   * Both resulting .so files were verified symbol-by-symbol
#     against the NDK r25c API-19 stub libraries (llvm-readelf
#     undefined set ⊆ stub-defined set, arm + x86, zero missing).
#     The API 21 builds fail that check (sigfillset & friends are
#     libc symbols only from API 21; at 19 they are header inlines,
#     which is why a rebuild — not a manifest edit — is required).
#
# The stock API 21 path (tools/build-manual.sh defaults) is untouched
# by this profile: different NDK, different AAR directory, different
# output directory.
set -euo pipefail

LEGPLAT="${LEGPLAT:-$HOME/workspace/.legplat}"
WS5="$LEGPLAT/ws5-api19"
NDK_DIR="$WS5/ndk/25.2.9519653"
NDK_ZIP="$WS5/dl/android-ndk-r25c-linux.zip"
# Official sha1 from dl.google.com/android/repository/repository2-1.xml
# (remotePackage ndk;25.2.9519653, archive android-ndk-r25c-linux.zip).
NDK_ZIP_SHA1="53af80a1cce9144025b81c78c8cd556bff42bd0e"
SINGBOX_SRC="${SINGBOX_SRC:-$LEGPLAT/build/sing-box-1.12.12}"
CORE_COPY="${CORE_COPY:-$LEGPLAT/build/sora-legacy-core}"
OUT_DIR="$WS5/aar19"
BIN_DIR="$WS5/bin"

export JAVA_HOME="${JAVA_HOME:-$LEGPLAT/jdk/jdk-17.0.20.1+1}"
export PATH="$JAVA_HOME/bin:$HOME/workspace/go/bin:$HOME/go/bin:$PATH"
export LANG=C.UTF-8 LC_ALL=C.UTF-8 JAVA_TOOL_OPTIONS=-Dfile.encoding=UTF-8
export TMPDIR="${TMPDIR:-$HOME/workspace/.build-tmp}"
export GOTMPDIR="$TMPDIR" GOCACHE="${GOCACHE:-$HOME/workspace/.gocache-v}"
export ANDROID_HOME="$LEGPLAT/android-sdk"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export ANDROID_NDK_HOME="$NDK_DIR"
mkdir -p "$TMPDIR" "$GOCACHE" "$WS5/dl" "$OUT_DIR" "$BIN_DIR"

# --- 1. NDK r25c (last NDK with an API 19 floor) ----------------------
if [ ! -f "$NDK_DIR/source.properties" ]; then
    if [ ! -f "$NDK_ZIP" ]; then
        curl -fL -C - --retry 5 -o "$NDK_ZIP" \
            https://dl.google.com/android/repository/android-ndk-r25c-linux.zip
    fi
    echo "$NDK_ZIP_SHA1  $NDK_ZIP" | sha1sum -c -
    mkdir -p "$WS5/ndk"
    unzip -qo "$NDK_ZIP" -d "$WS5/ndk"
    mv "$WS5/ndk/android-ndk-r25c" "$NDK_DIR"
fi
grep -q '"min": 19' "$NDK_DIR/meta/platforms.json"

# --- 2. mobileapi (official gomobile, this repo's core) ---------------
# Same byte-copy + tool-directive arrangement as the API 21 toolchain
# (gomobile bind requires x/mobile in the module graph; the repo's own
# go.mod is never touched).
(cd "$CORE_COPY" && GOTOOLCHAIN=auto GOFLAGS=-mod=mod "$HOME/go/bin/gomobile" bind \
    -target=android/arm,android/386 -androidapi 19 \
    -o "$OUT_DIR/mobileapi.aar" ./mobileapi)

# --- 3. libbox (sagernet gomobile v0.1.8, sing-box 1.12.12) -----------
# Args mirror cmd/internal/build_libbox buildAndroid() in the pin
# except -target/-androidapi; build_libbox hardcodes 21.
export GOBIN="$BIN_DIR"
export GOPROXY="file://$HOME/go/pkg/mod/cache/download" GOSUMDB=off
if [ ! -x "$BIN_DIR/gomobile" ]; then
    GOTOOLCHAIN=local GOFLAGS=-mod=mod "$HOME/workspace/go/bin/go" install \
        github.com/sagernet/gomobile/cmd/gomobile@v0.1.8 \
        github.com/sagernet/gomobile/cmd/gobind@v0.1.8
fi
export PATH="$BIN_DIR:$PATH"
(cd "$SINGBOX_SRC" && GOTOOLCHAIN=local GOFLAGS=-mod=mod "$BIN_DIR/gomobile" bind \
    -target android/arm,android/386 -androidapi 19 \
    -javapkg=io.nekohasekai -libname=box \
    -trimpath -buildvcs=false \
    -ldflags "-X github.com/sagernet/sing-box/constant.Version=1.12.12 -s -w -buildid= -checklinkname=0" \
    -tags with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api,with_conntrack,with_tailscale \
    -o "$OUT_DIR/libbox.aar" \
    ./experimental/libbox)

ls -lh "$OUT_DIR"
echo "OK: API 19 AARs in $OUT_DIR"
