package ch.chiavora.core

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

/** The Secret Key's entry is not biometric-bound (I8), so a new fingerprint cannot lose it. */
internal object DeviceKeys {
    const val MUK_WRAPPING_KEY_ALIAS = "ch.chiavora.muk.wrapping"

    const val SECRET_KEY_ALIAS = "ch.chiavora.secretkey"

    private const val KEYSTORE = "AndroidKeyStore"

    fun createMukWrappingKey(preferStrongBox: Boolean = true): SecretKey =
        generate(
            alias = MUK_WRAPPING_KEY_ALIAS,
            preferStrongBox = preferStrongBox,
        ) { builder ->
            builder
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true)
        }

    /** Biometric binding here would break I8, and `core`'s `check_i8` refuses it. */
    fun createSecretKeyEntry(preferStrongBox: Boolean = true): SecretKey =
        generate(
            alias = SECRET_KEY_ALIAS,
            preferStrongBox = preferStrongBox,
        ) { builder -> builder }

    private fun generate(
        alias: String,
        preferStrongBox: Boolean,
        configure: (KeyGenParameterSpec.Builder) -> KeyGenParameterSpec.Builder,
    ): SecretKey {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        val base = {
            configure(
                KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256),
            )
        }

        if (preferStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                generator.init(base().setIsStrongBoxBacked(true).build())
                return generator.generateKey()
            } catch (e: Exception) {
                android.util.Log.i(TAG, "StrongBox unavailable for $alias, falling back to TEE: $e")
            }
        }
        generator.init(base().build())
        return generator.generateKey()
    }

    fun unlockCipherForMuk(iv: ByteArray): Cipher {
        val key = loadKey(MUK_WRAPPING_KEY_ALIAS)
        return Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, key, javax.crypto.spec.GCMParameterSpec(GCM_TAG_BITS, iv))
        }
    }

    /** For the MUK's alias, authentication gates encryption too, so this needs the prompt. */
    fun loadForEncrypt(alias: String): Cipher =
        Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, loadKey(alias)) }

    fun loadKeyForDecrypt(alias: String, spec: javax.crypto.spec.GCMParameterSpec): Cipher =
        Cipher.getInstance("AES/GCM/NoPadding")
            .apply { init(Cipher.DECRYPT_MODE, loadKey(alias), spec) }

    fun exists(alias: String): Boolean =
        KeyStore.getInstance(KEYSTORE).apply { load(null) }.containsAlias(alias)

    fun delete(alias: String) {
        KeyStore.getInstance(KEYSTORE).apply { load(null) }.deleteEntry(alias)
    }

    private fun loadKey(alias: String): SecretKey {
        val store = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        return store.getKey(alias, null) as SecretKey
    }

    /** In `core`'s terms, so that `check_i8` checks the device and not only the source. */
    fun describe(alias: String): Pair<String, Boolean> {
        val key = loadKey(alias)
        val info = SecretKeyFactory
            .getInstance(key.algorithm, KEYSTORE)
            .getKeySpec(key, KeyInfo::class.java) as KeyInfo

        val backing = when {
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.S ->
                when (info.securityLevel) {
                    KeyProperties.SECURITY_LEVEL_STRONGBOX -> "SecureElement"
                    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TrustedExecutionEnvironment"
                    else -> "SoftwareOnly"
                }
            @Suppress("DEPRECATION")
            info.isInsideSecureHardware -> "TrustedExecutionEnvironment"
            else -> "SoftwareOnly"
        }
        return backing to info.isInvalidatedByBiometricEnrollment
    }

    private const val GCM_TAG_BITS = 128
    private const val TAG = "CHIAVORA-KEYS"
}
