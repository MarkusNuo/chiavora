plugins {
    // AGP 9 compiles Kotlin itself and refuses `org.jetbrains.kotlin.android`.
    id("com.android.application") version "9.4.0" apply false
}
