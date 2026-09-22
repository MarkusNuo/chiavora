package ch.chiavora.core

import android.util.Base64
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import java.io.File
import java.util.concurrent.Executor
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import uniffi.chiavora_ffi_mobile.MobileVault

/** The plaintext MUK passes through a Java `byte[]`, a recorded R4 deviation. */
internal object VaultKeys {
    private const val GCM_TAG_BITS = 128
    private const val WRAPPED_MUK_FILE = "muk.wrapped"
    private const val SECRET_KEY_FILE = "secret-key.wrapped"
    private const val ACCOUNT_ID_FILE = "account-id"

    suspend fun storeWrappedMukAuthenticated(
        activity: FragmentActivity,
        filesDir: File,
        executor: Executor,
        muk: ByteArray,
        reason: String,
    ) {
        // Always a fresh key: an invalidated key keeps its alias.
        if (DeviceKeys.exists(DeviceKeys.MUK_WRAPPING_KEY_ALIAS)) {
            DeviceKeys.delete(DeviceKeys.MUK_WRAPPING_KEY_ALIAS)
        }
        DeviceKeys.createMukWrappingKey()
        val cipher = DeviceKeys.loadForEncrypt(DeviceKeys.MUK_WRAPPING_KEY_ALIAS)
        val authenticated = authenticate(activity, executor, cipher, reason)
        val sealed = authenticated.doFinal(muk)
        File(filesDir, WRAPPED_MUK_FILE).writeText(
            Base64.encodeToString(authenticated.iv, Base64.NO_WRAP) + ":" +
                Base64.encodeToString(sealed, Base64.NO_WRAP),
        )
    }

    fun hasWrappedMuk(filesDir: File): Boolean = File(filesDir, WRAPPED_MUK_FILE).exists()

    fun mukKeyInvalidated(filesDir: File): Boolean {
        if (!hasWrappedMuk(filesDir)) return false
        return try {
            DeviceKeys.unlockCipherForMuk(readIv(filesDir))
            false
        } catch (e: android.security.keystore.KeyPermanentlyInvalidatedException) {
            android.util.Log.i(TAG, "MUK wrapping key invalidated by a biometric change: $e")
            true
        } catch (e: Exception) {
            android.util.Log.w(TAG, "MUK wrapping key unusable: $e")
            true
        }
    }

    suspend fun unlock(activity: FragmentActivity, filesDir: File, executor: Executor): MobileVault {
        val cipher = DeviceKeys.unlockCipherForMuk(readIv(filesDir))
        val authenticated =
            authenticate(activity, executor, cipher, "Your fingerprint releases the key that opens the vault")
        val sealed = readCiphertext(filesDir)

        var plaintext: ByteArray? = null
        try {
            plaintext = authenticated.doFinal(sealed)
            return MobileVault.fromStoredMuk(plaintext)
        } finally {
            plaintext?.fill(0)
        }
    }

    fun storeSecretKey(filesDir: File, presentation: ByteArray) {
        // A fresh entry too: a screen-lock change invalidates it but keeps the alias.
        if (DeviceKeys.exists(DeviceKeys.SECRET_KEY_ALIAS)) {
            DeviceKeys.delete(DeviceKeys.SECRET_KEY_ALIAS)
        }
        DeviceKeys.createSecretKeyEntry()
        val cipher = DeviceKeys.loadForEncrypt(DeviceKeys.SECRET_KEY_ALIAS)
        val sealed = cipher.doFinal(presentation)
        File(filesDir, SECRET_KEY_FILE).writeText(
            Base64.encodeToString(cipher.iv, Base64.NO_WRAP) + ":" +
                Base64.encodeToString(sealed, Base64.NO_WRAP),
        )
    }

    fun readSecretKey(filesDir: File): ByteArray {
        val file = File(filesDir, SECRET_KEY_FILE)
        val (iv, sealed) = split(file.readText())
        val key = DeviceKeys.loadKeyForDecrypt(
            DeviceKeys.SECRET_KEY_ALIAS,
            GCMParameterSpec(GCM_TAG_BITS, iv),
        )
        return key.doFinal(sealed)
    }

    fun hasSecretKey(filesDir: File): Boolean = File(filesDir, SECRET_KEY_FILE).exists()

    fun storeAccountId(filesDir: File, accountId: ByteArray) {
        File(filesDir, ACCOUNT_ID_FILE).writeBytes(accountId)
    }

    fun readAccountId(filesDir: File): ByteArray? {
        val file = File(filesDir, ACCOUNT_ID_FILE)
        return if (file.exists()) file.readBytes() else null
    }

    fun forget(filesDir: File) {
        File(filesDir, ACCOUNT_ID_FILE).delete()
        File(filesDir, WRAPPED_MUK_FILE).delete()
        File(filesDir, SECRET_KEY_FILE).delete()
        for (alias in listOf(DeviceKeys.MUK_WRAPPING_KEY_ALIAS, DeviceKeys.SECRET_KEY_ALIAS)) {
            if (DeviceKeys.exists(alias)) DeviceKeys.delete(alias)
        }
    }

    private fun readIv(filesDir: File): ByteArray =
        split(File(filesDir, WRAPPED_MUK_FILE).readText()).first

    private fun readCiphertext(filesDir: File): ByteArray =
        split(File(filesDir, WRAPPED_MUK_FILE).readText()).second

    private fun split(stored: String): Pair<ByteArray, ByteArray> {
        val parts = stored.split(":")
        require(parts.size == 2) { "the wrapped blob is not iv:ciphertext" }
        return Base64.decode(parts[0], Base64.NO_WRAP) to Base64.decode(parts[1], Base64.NO_WRAP)
    }

    /** `reason` is drawn over the lock screen, so callers pass a fixed string, never item data. */
    private suspend fun authenticate(
        activity: FragmentActivity,
        executor: Executor,
        cipher: Cipher,
        reason: String,
    ): Cipher =
        // UI-THREAD: the biometric prompt must be shown on the main thread; nothing else is.
        withContext(Dispatchers.Main) {
            suspendCancellableCoroutine { continuation ->
            val prompt = BiometricPrompt(
                activity,
                executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        val unlocked = result.cryptoObject?.cipher
                        if (unlocked == null) {
                            continuation.resumeWithException(
                                IllegalStateException("authentication succeeded without a CryptoObject"),
                            )
                        } else {
                            continuation.resume(unlocked)
                        }
                    }

                    override fun onAuthenticationError(code: Int, message: CharSequence) {
                        // Not counted: a cancel, a hardware error or the platform's lockout.
                        continuation.resumeWithException(IllegalStateException("biometric error $code: $message"))
                    }
                },
            )

            // LEAVES-WINDOW: drawn over the lock screen, so fixed strings only, never item data.
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Unlock Chiavora")
                .setSubtitle(reason)
                .setNegativeButtonText("Use password")
                .build()

                prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
            }
        }

    private const val TAG = "CHIAVORA-KEYS"
}
