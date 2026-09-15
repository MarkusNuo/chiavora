package ch.chiavora.core

import androidx.fragment.app.FragmentActivity
import expo.modules.kotlin.functions.Coroutine
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import uniffi.chiavora_ffi_mobile.KeystoreReport
import uniffi.chiavora_ffi_mobile.MobileVault
import uniffi.chiavora_ffi_mobile.checkKeystoreArrangement
import uniffi.chiavora_ffi_mobile.ffiSmoke
import uniffi.chiavora_ffi_mobile.generatePassphrase
import uniffi.chiavora_ffi_mobile.generatePassword
import uniffi.chiavora_ffi_mobile.generatorLimits
import uniffi.chiavora_ffi_mobile.mukForDeviceWrapping
import uniffi.chiavora_ffi_mobile.restoreFromOlderBackup

/** Every function returns what the UI needs to render, never key material. */
class ChiavoraCoreModule : Module() {

    override fun definition() = ModuleDefinition {
        Name("ChiavoraCore")

        AsyncFunction("ffiSmoke") {
            ffiSmoke()
        }

        AsyncFunction("enroll") Coroutine { password: ByteArray, secretKey: ByteArray, accountId: ByteArray, accountSalt: ByteArray, memoryKib: Int, iterations: Int ->
            val activity = appContext.currentActivity as? FragmentActivity
                ?: throw IllegalStateException("no FragmentActivity for BiometricPrompt")
            val files = androidContext().filesDir
            VaultKeys.forget(files)
            VaultKeys.storeSecretKey(files, secretKey)
            val muk = mukForDeviceWrapping(
                password, secretKey, accountId, accountSalt,
                memoryKib.toUInt(), iterations.toUInt(),
                DeviceKeys.describe(DeviceKeys.MUK_WRAPPING_KEY_ALIAS).first,
            )
            try {
                VaultKeys.storeWrappedMukAuthenticated(
                    activity,
                    files,
                    java.util.concurrent.Executors.newSingleThreadExecutor(),
                    muk,
                    "Confirm your fingerprint to protect this vault on this device",
                )
            } catch (e: Throwable) {
                // All or nothing: a failed wrap must not leave a Secret Key without a MUK.
                VaultKeys.forget(files)
                throw e
            } finally {
                muk.fill(0)
            }
            true
        }

        AsyncFunction("unlockWithPassword") Coroutine { password: ByteArray, accountId: ByteArray, accountSalt: ByteArray, memoryKib: Int, iterations: Int ->
            val activity = appContext.currentActivity as? FragmentActivity
                ?: throw IllegalStateException("no FragmentActivity for BiometricPrompt")
            val files = androidContext().filesDir
            var secretKey: ByteArray? = null
            try {
                secretKey = VaultKeys.readSecretKey(files)
                val vault = MobileVault.fromSecrets(
                    password, secretKey, accountId, accountSalt,
                    memoryKib.toUInt(), iterations.toUInt(),
                )
                val muk = mukForDeviceWrapping(
                    password, secretKey, accountId, accountSalt,
                    memoryKib.toUInt(), iterations.toUInt(),
                    DeviceKeys.describe(DeviceKeys.MUK_WRAPPING_KEY_ALIAS).first,
                )
                try {
                    VaultKeys.storeWrappedMukAuthenticated(
                        activity,
                        files,
                        java.util.concurrent.Executors.newSingleThreadExecutor(),
                        muk,
                        "Confirm your fingerprint to use it for unlocking again",
                    )
                } finally {
                    muk.fill(0)
                }
                mapOf(
                    "mukLen" to vault.mukLen().toInt(),
                    "rollbackProtection" to vault.rollbackProtection(
                        storePath(files),
                        AnchorStore.Backed(files),
                    ),
                )
            } finally {
                secretKey?.fill(0)
            }
        }

        AsyncFunction("unlockWithBiometric") Coroutine { ->
            val activity = appContext.currentActivity as? FragmentActivity
                ?: throw IllegalStateException("no FragmentActivity for BiometricPrompt")
            val files = androidContext().filesDir
            // `Coroutine` because the prompt suspends; it still runs on Expo's dispatcher.
            val vault = VaultKeys.unlock(
                activity,
                files,
                java.util.concurrent.Executors.newSingleThreadExecutor(),
            )
            mapOf(
                "mukLen" to vault.mukLen().toInt(),
                "rollbackProtection" to vault.rollbackProtection(
                    storePath(files),
                    AnchorStore.Backed(files),
                ),
            )
        }

        AsyncFunction("vaultState") {
            val files = androidContext().filesDir
            mapOf(
                "hasSecretKey" to VaultKeys.hasSecretKey(files),
                "hasWrappedMuk" to VaultKeys.hasWrappedMuk(files),
                "mukKeyInvalidated" to VaultKeys.mukKeyInvalidated(files),
            )
        }

        AsyncFunction("keystoreReport") {
            val (mukBacking, mukInvalidated) = DeviceKeys.describe(DeviceKeys.MUK_WRAPPING_KEY_ALIAS)
            val (skBacking, skInvalidated) = DeviceKeys.describe(DeviceKeys.SECRET_KEY_ALIAS)
            val report = KeystoreReport(mukBacking, mukInvalidated, skBacking, skInvalidated)
            // Throws if `core` refuses the arrangement.
            checkKeystoreArrangement(report)
            mapOf(
                "mukBacking" to mukBacking,
                "mukInvalidatedByEnrollment" to mukInvalidated,
                "secretKeyBacking" to skBacking,
                "secretKeyInvalidatedByEnrollment" to skInvalidated,
            )
        }

        AsyncFunction("restoreFromOlderBackup") Coroutine { password: ByteArray, accountId: ByteArray, accountSalt: ByteArray, memoryKib: Int, iterations: Int, discardingAfter: Double ->
            val files = androidContext().filesDir
            var secretKey: ByteArray? = null
            try {
                secretKey = VaultKeys.readSecretKey(files)
                val vault = restoreFromOlderBackup(
                    storePath(files),
                    AnchorStore.Backed(files),
                    password, secretKey, accountId, accountSalt,
                    memoryKib.toUInt(), iterations.toUInt(),
                    discardingAfter.toULong(),
                )
                vault.mukLen().toInt()
            } finally {
                secretKey?.fill(0)
            }
        }

        AsyncFunction("forgetDevice") {
            VaultKeys.forget(androidContext().filesDir)
            true
        }

        AsyncFunction("generatorLimits") {
            val limits = generatorLimits()
            mapOf(
                "maxLength" to limits.maxLength.toInt(),
                "maxWords" to limits.maxWords.toInt(),
                "wordCount" to limits.wordCount.toInt(),
                "symbols" to limits.symbols,
                "wordlistAttribution" to limits.wordlistAttribution,
                "wordlistSource" to limits.wordlistSource,
            )
        }

        AsyncFunction("generatePassword") { length: Int, lowercase: Boolean, uppercase: Boolean, digits: Boolean, symbols: Boolean, excludeAmbiguous: Boolean, requireOneOfEach: Boolean ->
            val out = generatePassword(
                length.toUInt(), lowercase, uppercase, digits, symbols,
                excludeAmbiguous, requireOneOfEach,
            )
            mapOf("value" to out.value, "entropyBits" to out.entropyBits)
        }

        AsyncFunction("generatePassphrase") { words: Int, separator: String, capitalise: Boolean ->
            val out = generatePassphrase(words.toUInt(), separator, capitalise)
            mapOf("value" to out.value, "entropyBits" to out.entropyBits)
        }

        // One copy per build variant; only the debug one registers the measurement harness.
        harnessDefinition()
    }

    /** Kept out of backups by `with-chiavora-backup.js`. */
    private fun storePath(files: java.io.File): String =
        java.io.File(files, "vault.db").absolutePath

    private fun androidContext(): android.content.Context =
        appContext.reactContext
            ?: throw IllegalStateException("no React context: the module is being torn down")
}
