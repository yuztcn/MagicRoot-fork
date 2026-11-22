plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.jetbrains.compose")
}

android {
    namespace = "com.aoki.magicroot"
    compileSdk = 37
    buildToolsVersion = "37.0.0"

    defaultConfig {
        val credMode = (project.findProperty("magicrootCredMode") as String?)
            ?.trim()?.lowercase() ?: "fake"
        require(credMode == "real" || credMode == "fake") {
            "magicrootCredMode must be real or fake"
        }
        buildConfigField("String", "CRED_MODE_DEFAULT", "\"$credMode\"")
        applicationId = "com.aoki.magicroot"
        minSdk = 34
        targetSdk = 37
        versionCode = 13
        versionName = "1.0.6"

        ndk {
            // The exploit assets and the only supported device are arm64.
            abiFilters += "arm64-v8a"
        }
    }

    signingConfigs {
        create("release") {
            val ks = System.getenv("MAGICROOT_KEYSTORE")
            val storePass = System.getenv("MAGICROOT_STORE_PASS")
            val keyPass = System.getenv("MAGICROOT_KEY_PASS")
            if (!ks.isNullOrBlank()) {
                if (storePass.isNullOrBlank() || keyPass.isNullOrBlank()) {
                    throw GradleException(
                        "MAGICROOT_STORE_PASS and MAGICROOT_KEY_PASS must be set when MAGICROOT_KEYSTORE is provided"
                    )
                }
                storeFile = file(ks)
                storePassword = storePass
                keyAlias = System.getenv("MAGICROOT_KEY_ALIAS")?.takeIf { it.isNotBlank() } ?: "magicroot"
                keyPassword = keyPass
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            val releaseSign = signingConfigs.getByName("release")
            if (releaseSign.storeFile != null) {
                signingConfig = releaseSign
            } else if (gradle.startParameter.taskNames.any {
                    it.contains("assembleRelease", ignoreCase = true) ||
                        it.contains("packageRelease", ignoreCase = true) ||
                        it.contains("bundleRelease", ignoreCase = true)
                }) {
                throw GradleException(
                    "Release signing requires MAGICROOT_KEYSTORE, MAGICROOT_STORE_PASS, and MAGICROOT_KEY_PASS environment variables"
                )
            }
        }
    }

    buildFeatures {
        buildConfig = true
        aidl = false
        shaders = false
        resValues = false
    }

    androidResources {
        generateLocaleConfig = false
        localeFilters += listOf("en", "zh")
    }

    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }

    lint {
        checkReleaseBuilds = false
        abortOnError = false
    }

    packaging {
        jniLibs {
            useLegacyPackaging = true
            keepDebugSymbols += setOf("**/libandroidx.graphics.path.so")
        }
        resources.excludes += setOf(
            "META-INF/LICENSE*",
            "META-INF/NOTICE*",
            "META-INF/**/LICENSE.txt",
            "META-INF/**/NOTICE.txt",
            "META-INF/**/LICENSE",
            "META-INF/**/NOTICE",
            "META-INF/*.version",
            "META-INF/*.kotlin_module",
            "META-INF/DEPENDENCIES",
            "META-INF/INDEX.LIST",
            "META-INF/*.md",
        )
    }

    sourceSets.getByName("main") {
        assets.directories.add("../../app/assets")
        res.directories.add("../../app/res")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

configurations.configureEach {
    // The app does not install its own baseline profile; excluding this
    // optional runtime removes the generated assets/dexopt/baseline.prof/profm.
    exclude(group = "androidx.profileinstaller", module = "profileinstaller")
}

dependencies {
    implementation("androidx.activity:activity:1.13.0")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("top.yukonga.miuix.kmp:miuix-ui-android:0.9.4")
    implementation("top.yukonga.miuix.kmp:miuix-preference-android:0.9.4")
    implementation("top.yukonga.miuix.kmp:miuix-blur-android:0.9.4")
    implementation("org.jetbrains.compose.runtime:runtime:1.12.2")
    implementation("org.jetbrains.compose.foundation:foundation:1.12.2")
    implementation("org.jetbrains.compose.ui:ui:1.12.2")
    implementation(fileTree("../../app/libs") { include("shizuku-*.jar") })
}



