// Canonical build for a developer machine. Versions are pinned; the
// sandbox this tree was authored in cannot resolve them (JVM network
// is blocked there), so the sandbox build is the manual pipeline in
// tools/build-manual.sh — see README.md.
plugins {
    id("com.android.application") version "8.5.2" apply false
    id("org.jetbrains.kotlin.android") version "2.0.21" apply false
}
