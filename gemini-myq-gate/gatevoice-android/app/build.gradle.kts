plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.gatevoice.app"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.gatevoice.app"
        minSdk = 29
        targetSdk = 34
        versionCode = 6
        versionName = "0.6"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    // Stable signing key committed to the repo so every CI build installs as a
    // clean UPDATE over the previous one (no uninstall, permissions kept).
    // This is a throwaway key for a personal sideloaded app, not a secret.
    signingConfigs {
        create("stable") {
            storeFile = file("gatevoice-release.jks")
            storePassword = "gatevoice"
            keyAlias = "gatevoice"
            keyPassword = "gatevoice"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.getByName("stable")
        }
        debug {
            // CI ships the debug APK for sideloading; sign it with the stable
            // key so updates never hit a signature mismatch.
            signingConfig = signingConfigs.getByName("stable")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        viewBinding = true
        buildConfig = true
    }
    // The Vosk model is large; don't compress it in the APK.
    androidResources {
        noCompress += listOf("mdl", "conf", "fst", "int", "vector", "carpa", "txt", "dubm", "mat")
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")

    // Fully offline speech recognition + keyword spotting.
    implementation("com.alphacephei:vosk-android:0.3.47")
    implementation("net.java.dev.jna:jna:5.13.0@aar")

    testImplementation("junit:junit:4.13.2")
}
