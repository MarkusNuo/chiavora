package ch.chiavora.core

import androidx.fragment.app.FragmentActivity
import expo.modules.kotlin.functions.Coroutine
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import uniffi.chiavora_ffi_mobile.ItemField
import uniffi.chiavora_ffi_mobile.lockPolicy
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
    /** A Rust-owned handle, never a key; volatile so a lock is seen at once on every thread. */
    @Volatile
    private var session: MobileVault? = null

    @Volatile
    private var sessionAccountId: ByteArray? = null

    private val lockController = LockController { reason -> dropSession(reason) }

    override fun definition() = ModuleDefinition {
        Name("ChiavoraCore")

        Events("onLock")

        AsyncFunction("ffiSmoke") {
            ffiSmoke()
        }

        AsyncFunction("enroll") Coroutine { password: ByteArray, secretKey: ByteArray, accountId: ByteArray, accountSalt: ByteArray, memoryKib: Int, iterations: Int ->
            val activity = appContext.currentActivity as? FragmentActivity
                ?: throw IllegalStateException("no FragmentActivity for BiometricPrompt")
            val files = androidContext().filesDir
            VaultKeys.forget(files)
            VaultKeys.storeSecretKey(files, secretKey)
            VaultKeys.storeAccountId(files, accountId)
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
                val protection = vault.rollbackProtection(
                    storePath(files),
                    AnchorStore.Backed(files),
                )
                // Kept only once nothing above can throw, so a failed unlock leaves no session.
                session = vault
                sessionAccountId = accountId
                armAutoLock()
                mapOf(
                    "mukLen" to vault.mukLen().toInt(),
                    "rollbackProtection" to protection,
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
            val protection = vault.rollbackProtection(
                storePath(files),
                AnchorStore.Backed(files),
            )
            session = vault
            sessionAccountId = VaultKeys.readAccountId(files)
                ?: throw IllegalStateException("this device is enrolled without an account identifier")
            armAutoLock()
            mapOf(
                "mukLen" to vault.mukLen().toInt(),
                "rollbackProtection" to protection,
            )
        }

        AsyncFunction("lock") {
            // Through the controller, so manual and automatic locks take one path.
            lockController.lockNow()
            true
        }

        AsyncFunction("isUnlocked") {
            session != null
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
            dropSession(LockController.LockReason.MANUAL)
            VaultKeys.forget(androidContext().filesDir)
            true
        }

        AsyncFunction("lockPolicy") {
            val policy = lockPolicy()
            mapOf(
                "idleTimeoutSeconds" to policy.idleTimeoutSeconds.toInt(),
                "minIdleTimeoutSeconds" to policy.minIdleTimeoutSeconds.toInt(),
                "maxIdleTimeoutSeconds" to policy.maxIdleTimeoutSeconds.toInt(),
                "clipboardTtlSeconds" to policy.clipboardTtlSeconds.toInt(),
                "maxFailedAttempts" to policy.maxFailedAttempts.toInt(),
                "provisional" to policy.provisional,
            )
        }

        AsyncFunction("isProvisioned") {
            val vault = requireSession()
            val files = androidContext().filesDir
            vault.isProvisioned(storePath(files), AnchorStore.Backed(files))
        }

        AsyncFunction("provisionAccount") {
            val vault = requireSession()
            val files = androidContext().filesDir
            vault.provisionAccount(storePath(files), AnchorStore.Backed(files), requireAccountId())
            true
        }

        /** Each opens the store, so the rollback check runs per call, not once per session. */
        AsyncFunction("listItems") {
            val vault = requireSession()
            val files = androidContext().filesDir
            vault.listItems(storePath(files), AnchorStore.Backed(files), requireAccountId()).map { row ->
                mapOf(
                    "itemId" to row.itemId,
                    "version" to row.version.toDouble(),
                    "kind" to row.kind,
                    "title" to row.title,
                    "username" to row.username,
                )
            }
        }

        AsyncFunction("readItem") { itemId: String ->
            val vault = requireSession()
            val files = androidContext().filesDir
            val detail =
                vault.readItem(storePath(files), AnchorStore.Backed(files), requireAccountId(), itemId)
            mapOf(
                "itemId" to detail.itemId,
                "kind" to detail.kind,
                "fields" to detail.fields.map { field ->
                    mapOf(
                        "name" to field.name,
                        "value" to field.value,
                        "concealed" to field.concealed,
                    )
                },
            )
        }

        AsyncFunction("createItem") { kind: String, fields: List<Map<String, Any?>> ->
            val vault = requireSession()
            val files = androidContext().filesDir
            vault.createItem(
                storePath(files),
                AnchorStore.Backed(files),
                requireAccountId(),
                kind,
                itemFields(fields),
            )
        }

        AsyncFunction("updateItem") { itemId: String, kind: String, fields: List<Map<String, Any?>> ->
            val vault = requireSession()
            val files = androidContext().filesDir
            vault.updateItem(
                storePath(files),
                AnchorStore.Backed(files),
                requireAccountId(),
                itemId,
                kind,
                itemFields(fields),
            ).toDouble()
        }

        AsyncFunction("deleteItem") { itemId: String ->
            val vault = requireSession()
            val files = androidContext().filesDir
            vault.deleteItem(storePath(files), AnchorStore.Backed(files), requireAccountId(), itemId)
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

    private fun armAutoLock() {
        lockController.arm(lockPolicy().idleTimeoutSeconds.toLong() * 1000L)
        (appContext.currentActivity)?.let { lockController.watchTouches(it) }
    }

    /** Kept out of backups by `with-chiavora-backup.js`. */
    private fun storePath(files: java.io.File): String =
        java.io.File(files, "vault.db").absolutePath

    /** The event goes after the state is cleared, so a screen calling back finds it locked. */
    private fun dropSession(reason: LockController.LockReason) {
        session = null
        sessionAccountId = null
        lockController.disarm()
        sendEvent(
            "onLock",
            mapOf("reason" to reason.name.lowercase()),
        )
    }

    private fun requireSession(): MobileVault =
        session ?: throw IllegalStateException("no vault is open: unlock first")

    private fun requireAccountId(): ByteArray =
        sessionAccountId
            ?: throw IllegalStateException("the open session has no account identifier")

    private fun itemFields(fields: List<Map<String, Any?>>): List<ItemField> =
        fields.map { field ->
            val name = field["name"] as? String
                ?: throw IllegalArgumentException("a field arrived with no name")
            val value = field["value"] as? String
                ?: throw IllegalArgumentException("field '$name' arrived with no value")
            // `concealed` is decided by `core`, never by the screen.
            ItemField(name, value, false)
        }

    private fun androidContext(): android.content.Context =
        appContext.reactContext
            ?: throw IllegalStateException("no React context: the module is being torn down")
}
