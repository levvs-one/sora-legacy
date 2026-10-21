#!/usr/bin/env bash
# Manual APK pipeline for environments where Gradle cannot run —
# concretely this sandbox, where JVM network access is blocked by the
# host (see ../../README.md "Building"), so AGP / the Kotlin Gradle
# plugin cannot be resolved. On a developer machine prefer Gradle:
#   cp <mobileapi.aar> <libbox.aar> app/libs/ && ./gradlew assembleDebug
#
# Pipeline (all tools are the official ones, no substitutes):
#   kotlinc (standalone compiler zip, sha256-pinned below)
#     -> classes for our Kotlin sources against android.jar + AAR jars
#   aapt2 compile + link (resources + manifest -> base APK + R class)
#   d8 (Kotlin classes + AAR classes + kotlin-stdlib -> classes.dex)
#   zip (base APK + classes.dex + lib/<abi>/*.so from both AARs)
#   zipalign -> apksigner (debug key generated with keytool)
#
# Output: $LEGPLAT/apk/app-debug.apk, plus badging/verify logs.
# Re-runnable: all intermediates live in $LEGPLAT/build-manual and are
# recreated from scratch on every run.
set -euo pipefail

ANDROID_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LEGPLAT="${LEGPLAT:-$HOME/workspace/.legplat}"
export JAVA_HOME="${JAVA_HOME:-$LEGPLAT/jdk/jdk-17.0.20.1+1}"
export PATH="$JAVA_HOME/bin:$PATH"
export LANG=C.UTF-8 LC_ALL=C.UTF-8

SDK="$LEGPLAT/android-sdk"
ANDROID_JAR="$SDK/platforms/android-34/android.jar"
BUILD_TOOLS="$SDK/build-tools/34.0.0"
AAR_DIR="$LEGPLAT/aar"
WORK="$LEGPLAT/build-manual"
OUT="$LEGPLAT/apk"
KEYSTORE="$LEGPLAT/debug.keystore"

KOTLIN_VERSION="2.0.21"
KOTLIN_ZIP="$LEGPLAT/downloads/kotlin-compiler-$KOTLIN_VERSION.zip"
# Official sha256 from the JetBrains GitHub release asset
# kotlin-compiler-2.0.21.zip.sha256 (verified 2026-10-21).
KOTLIN_ZIP_SHA256="0352c0a45bd22f80f6b26e485cd04da8047baa5de54865281fb9f89a4a7bcf2a"
KOTLINC_HOME="$LEGPLAT/kotlin/kotlinc"

# --- 0. toolchain ----------------------------------------------------
if [ ! -x "$KOTLINC_HOME/bin/kotlinc" ]; then
    if [ ! -f "$KOTLIN_ZIP" ]; then
        curl -fL --retry 3 -o "$KOTLIN_ZIP" \
            "https://github.com/JetBrains/kotlin/releases/download/v$KOTLIN_VERSION/kotlin-compiler-$KOTLIN_VERSION.zip"
    fi
    echo "$KOTLIN_ZIP_SHA256  $KOTLIN_ZIP" | sha256sum -c -
    mkdir -p "$LEGPLAT/kotlin"
    unzip -qo "$KOTLIN_ZIP" -d "$LEGPLAT/kotlin"
fi
for tool in "$ANDROID_JAR" "$BUILD_TOOLS/aapt2" "$BUILD_TOOLS/d8" \
            "$BUILD_TOOLS/zipalign" "$BUILD_TOOLS/apksigner" \
            "$AAR_DIR/mobileapi.aar" "$AAR_DIR/libbox.aar"; do
    [ -e "$tool" ] || { echo "missing: $tool" >&2; exit 1; }
done

rm -rf "$WORK"
mkdir -p "$WORK/aar-mobile" "$WORK/aar-libbox" "$WORK/classes" \
         "$WORK/dex" "$WORK/stage" "$OUT"

# --- 1. AAR contents ---------------------------------------------------
unzip -qo "$AAR_DIR/mobileapi.aar" -d "$WORK/aar-mobile"
unzip -qo "$AAR_DIR/libbox.aar" -d "$WORK/aar-libbox"

# Both AARs embed the gomobile go.* proxy classes. A dex can hold a
# class once, so the mobileapi copy of go/** is dropped and libbox's
# copy is used for both (javap shows its Seq API is the superset —
# only destroyRef() visibility differs). See README "Two gomobile
# AARs, one go.Seq".
cp "$WORK/aar-mobile/classes.jar" "$WORK/mobileapi-classes.jar"
zip -dq "$WORK/mobileapi-classes.jar" 'go/*' >/dev/null
LIBBOX_JAR="$WORK/aar-libbox/classes.jar"
MOBILE_JAR="$WORK/mobileapi-classes.jar"

# --- 2. resources + manifest (aapt2) ----------------------------------
"$BUILD_TOOLS/aapt2" compile --dir "$ANDROID_DIR/app/src/main/res" -o "$WORK/res.zip"
"$BUILD_TOOLS/aapt2" link \
    -I "$ANDROID_JAR" \
    --manifest "$ANDROID_DIR/app/src/main/AndroidManifest.xml" \
    --java "$WORK/gen" \
    --min-sdk-version 21 --target-sdk-version 34 \
    --version-code 1 --version-name 0.1.0 \
    -o "$WORK/base.apk" "$WORK/res.zip"

# --- 3. Kotlin -> classes ----------------------------------------------
find "$ANDROID_DIR/app/src/main/java" -name '*.kt' > "$WORK/sources.txt"
find "$WORK/gen" -name '*.java' >> "$WORK/sources.txt"
"$KOTLINC_HOME/bin/kotlinc" \
    -classpath "$ANDROID_JAR:$LIBBOX_JAR:$WORK/mobileapi-classes.jar" \
    -jvm-target 17 \
    -d "$WORK/classes" \
    @"$WORK/sources.txt"

# --- 4. dex --------------------------------------------------------------
# Program inputs: our classes (d8 takes archives, not directories, so
# they are jarred first), both AAR jars (mobileapi one already
# de-duplicated), and the Kotlin stdlib from the compiler zip.
jar cf "$WORK/app-classes.jar" -C "$WORK/classes" .
"$BUILD_TOOLS/d8" \
    --min-api 21 \
    --lib "$ANDROID_JAR" \
    --output "$WORK/dex" \
    "$WORK/app-classes.jar" "$LIBBOX_JAR" "$MOBILE_JAR" \
    "$KOTLINC_HOME/lib/kotlin-stdlib.jar"

# --- 5. assemble APK -------------------------------------------------------
cp "$WORK/base.apk" "$WORK/stage/app-unsigned.apk"
cd "$WORK/stage"
cp "$WORK/dex/classes.dex" .
mkdir -p lib
for abi in armeabi-v7a arm64-v8a x86 x86_64; do
    mkdir -p "lib/$abi"
    cp "$WORK/aar-mobile/jni/$abi/libgojni.so" "lib/$abi/"
    cp "$WORK/aar-libbox/jni/$abi/libbox.so" "lib/$abi/"
done
# Native libs stored uncompressed (-0) and page-aligned by zipalign -p,
# as Android requires for direct mmap loading from the APK.
zip -q -0 app-unsigned.apk classes.dex lib/*/*.so
"$BUILD_TOOLS/zipalign" -p -f 4 app-unsigned.apk app-aligned.apk

# --- 6. sign (debug) ---------------------------------------------------------
if [ ! -f "$KEYSTORE" ]; then
    # Debug key only — explicitly NOT a release identity.
    keytool -genkeypair -keystore "$KEYSTORE" -storepass android -keypass android \
        -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10950 \
        -dname "CN=Android Debug,O=Sora Legacy,C=US"
fi
"$BUILD_TOOLS/apksigner" sign \
    --ks "$KEYSTORE" --ks-pass pass:android --key-pass pass:android \
    --ks-key-alias androiddebugkey \
    --out "$OUT/app-debug.apk" app-aligned.apk

# --- 7. proof ------------------------------------------------------------------
"$BUILD_TOOLS/apksigner" verify --print-certs --verbose "$OUT/app-debug.apk" | tee "$OUT/apksigner-verify.txt"
"$BUILD_TOOLS/aapt2" dump badging "$OUT/app-debug.apk" | tee "$OUT/aapt2-badging.txt"
ls -l "$OUT/app-debug.apk"
echo "OK: $OUT/app-debug.apk"
