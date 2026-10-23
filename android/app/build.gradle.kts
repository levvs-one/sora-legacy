plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Product version, aligned with the repository release. This is the
// single source for the app version: versionName takes it verbatim
// and versionCode is computed from it as
// major*10000 + minor*100 + patch (0.2.3 -> 203), so the code grows
// monotonically with every release. tools/build-manual.sh reads
// productVersionName from this file and applies the same rule —
// neither pipeline carries a second version literal.
val productVersionName = "0.2.3"
val productVersionCode = productVersionName.split(".").let { parts ->
    parts[0].toInt() * 10000 + parts[1].toInt() * 100 + parts[2].toInt()
}

android {
    namespace = "one.levvs.sora.legacy"
    compileSdk = 34

    defaultConfig {
        applicationId = "one.levvs.sora.legacy"
        // minSdk 21 is a fact-driven floor, not a taste: the gomobile
        // AARs are bound with -androidapi 21, VpnService.Builder is
        // complete enough from API 21, and below 21 the platform TLS /
        // Conscrypt story cannot carry the protocols the core renders.
        // See README.md ("Why minSdk 21").
        minSdk = 21
        targetSdk = 34
        // Version comes from productVersionName / productVersionCode
        // at the top of this file. The API 19 tier is built by the
        // same manual pipeline from the same source (only minSdk,
        // AARs and ABIs differ), so both tiers carry this one code.
        versionCode = productVersionCode
        versionName = productVersionName
        ndk {
            // Both AARs ship exactly these four ABIs.
            abiFilters += listOf("armeabi-v7a", "arm64-v8a", "x86", "x86_64")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    packaging {
        // Both gomobile AARs embed the same go.* proxy classes; AGP's
        // dex merger must keep a single copy (the libbox one, whose
        // Seq API is the superset). See README.md.
        resources {
            excludes += "META-INF/*"
        }
    }
}

dependencies {
    // Deliberately the whole dependency list: Kotlin stdlib plus the
    // two gomobile AARs produced from this repository's core and from
    // sing-box 1.12.12's libbox. No AndroidX, no Compose — framework
    // Views only, so the app builds offline and stays installable on
    // API 21. Drop the AARs into app/libs/ (they are git-ignored).
    implementation("org.jetbrains.kotlin:kotlin-stdlib:2.0.21")
    implementation(files("libs/mobileapi.aar"))
    implementation(files("libs/libbox.aar"))
}
