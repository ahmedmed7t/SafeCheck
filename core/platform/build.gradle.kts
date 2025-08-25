plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.androidLibrary)
}

kotlin {
    androidTarget {
        compilations.all {
            kotlinOptions {
                jvmTarget = "11"
            }
        }
    }
    
    iosX64()
    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        commonMain.dependencies {
            // Core domain dependency
            implementation(projects.core.domain)
            
            // Coroutines
            implementation(libs.kotlinx.coroutines.core)
            
            // DateTime
            implementation(libs.kotlinx.datetime)
        }
        
        androidMain.dependencies {
            implementation(libs.androidx.core.ktx)
            
            // DateTime (explicit for Android)
            implementation(libs.kotlinx.datetime)
            
            // Camera and QR scanning
            implementation("androidx.camera:camera-core:1.3.1")
            implementation("androidx.camera:camera-camera2:1.3.1")
            implementation("androidx.camera:camera-lifecycle:1.3.1")
            implementation("androidx.camera:camera-view:1.3.1")
            
            // ML Kit for QR code scanning
            implementation("com.google.mlkit:barcode-scanning:17.2.0")
            
            // Permissions
            implementation("androidx.activity:activity-ktx:1.8.2")
            
            // WorkManager for background tasks
            implementation("androidx.work:work-runtime-ktx:2.9.0")
        }
        
        iosMain.dependencies {
            // iOS-specific networking and system frameworks will be accessed via platform APIs
        }
        
        commonTest.dependencies {
            implementation(libs.kotlin.test)
            implementation(libs.kotlinx.coroutines.test)
        }
    }
}

android {
    namespace = "com.nexable.safecheck.core.platform"
    compileSdk = libs.versions.android.compileSdk.get().toInt()
    
    defaultConfig {
        minSdk = libs.versions.android.minSdk.get().toInt()
    }
    
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}
