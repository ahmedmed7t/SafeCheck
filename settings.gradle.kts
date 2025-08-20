rootProject.name = "SafeCheck"
enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

pluginManagement {
    repositories {
        google {
            mavenContent {
                includeGroupAndSubgroups("androidx")
                includeGroupAndSubgroups("com.android")
                includeGroupAndSubgroups("com.google")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google {
            mavenContent {
                includeGroupAndSubgroups("androidx")
                includeGroupAndSubgroups("com.android")
                includeGroupAndSubgroups("com.google")
            }
        }
        mavenCentral()
    }
}

include(":composeApp")
include(":shared")

// Core modules
include(":core:domain")
include(":core:data")
include(":core:net")
include(":core:platform")

// Feature modules
include(":feature:urlscan")
include(":feature:emailscan")
include(":feature:filescan")
include(":feature:history")
include(":feature:settings")
