plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Tiny "companion" launchers: one per device. Each is a separate installed app
// with its own voice-launchable name ("GateVoice Front/One/Two/Three"); on
// launch it fires the gatevoice:// deep link that GateVoice's ActionActivity
// handles, so GateVoice (which holds the accessibility service) taps myQ.
// Built as product flavors so one codebase yields four APKs.

android {
    namespace = "com.gatevoice.companion"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.gatevoice.companion"
        minSdk = 29
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }

    signingConfigs {
        create("stable") {
            storeFile = file("../app/gatevoice-release.jks")
            storePassword = "gatevoice"
            keyAlias = "gatevoice"
            keyPassword = "gatevoice"
        }
    }

    buildTypes {
        debug { signingConfig = signingConfigs.getByName("stable") }
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("stable")
        }
    }

    flavorDimensions += "device"
    productFlavors {
        create("gate") {
            dimension = "device"
            applicationIdSuffix = ".gate"
            resValue("string", "app_name", "GateVoice Front")
            buildConfigField("String", "DEVICE", "\"Gate\"")
            buildConfigField("String", "GVACTION", "\"open\"")
        }
        create("door1") {
            dimension = "device"
            applicationIdSuffix = ".door1"
            resValue("string", "app_name", "GateVoice One")
            buildConfigField("String", "DEVICE", "\"Garage Door 1\"")
            buildConfigField("String", "GVACTION", "\"open\"")
        }
        create("door2") {
            dimension = "device"
            applicationIdSuffix = ".door2"
            resValue("string", "app_name", "GateVoice Two")
            buildConfigField("String", "DEVICE", "\"Garage Door 2\"")
            buildConfigField("String", "GVACTION", "\"open\"")
        }
        create("door3") {
            dimension = "device"
            applicationIdSuffix = ".door3"
            resValue("string", "app_name", "GateVoice Three")
            buildConfigField("String", "DEVICE", "\"Garage Door 3\"")
            buildConfigField("String", "GVACTION", "\"open\"")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures { buildConfig = true }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
}
