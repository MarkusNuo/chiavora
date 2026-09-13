plugins {
    id("com.android.application")
}

android {
    namespace = "ch.chiavora.harness"
    compileSdk = 36

    defaultConfig {
        applicationId = "ch.chiavora.harness"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "harness"
        ndk {
            // The reference device is arm64.
            abiFilters += "arm64-v8a"
        }
    }

    buildTypes {
        // Release, so the derivation is measured optimised; debuggable so `adb`
        // can drive it, and not minified so nothing is renamed under JNA.
        getByName("release") {
            isMinifyEnabled = false
            isDebuggable = true
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    // JNA loads the library from the extracted native-library directory.
    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        getByName("main") {
            // AGP 9 reads `java` and `kotlin` separately, so the generated
            // bindings have to be in both.
            java.srcDirs("src/main/kotlin", "src/main/generated")
            kotlin.srcDirs("src/main/kotlin", "src/main/generated")
            jniLibs.srcDirs("src/main/jniLibs")
        }
    }

    lint {
        abortOnError = false
    }
}

dependencies {
    // The `@aar` build carries JNA's native dispatcher for each ABI.
    implementation("net.java.dev.jna:jna:5.19.1@aar")
}
