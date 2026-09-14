package ch.chiavora.core

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Base64
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import uniffi.chiavora_ffi_mobile.AnchorException
import uniffi.chiavora_ffi_mobile.DeviceAnchorStorage

/** Sealed under a Keystore key, so restoring an old copy with the database fails the read. */
object AnchorStore {

    const val ALIAS = "ch.chiavora.anchor"
    private const val FILE = "rollback-anchor.bin"
    private const val GCM_TAG_BITS = 128
    private const val KEYSTORE = "AndroidKeyStore"

    class Backed(private val filesDir: File) : DeviceAnchorStorage {

        override fun read(): ULong? {
            val file = File(filesDir, FILE)
            if (!file.exists()) {
                // Absent means trust-on-first-use; unreadable must refuse the unlock.
                return null
            }
            return try {
                val (iv, sealed) = file.readText().split(":").let {
                    Base64.decode(it[0], Base64.NO_WRAP) to Base64.decode(it[1], Base64.NO_WRAP)
                }
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(
                    Cipher.DECRYPT_MODE,
                    loadKey(),
                    GCMParameterSpec(GCM_TAG_BITS, iv),
                )
                String(cipher.doFinal(sealed)).toULong()
            } catch (e: Throwable) {
                throw AnchorException.Unreadable()
            }
        }

        override fun write(generation: ULong) {
            try {
                ensureKey()
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.ENCRYPT_MODE, loadKey())
                val sealed = cipher.doFinal(generation.toString().toByteArray())
                val text = Base64.encodeToString(cipher.iv, Base64.NO_WRAP) + ":" +
                    Base64.encodeToString(sealed, Base64.NO_WRAP)
                // On disk before returning, as `core` requires.
                val target = File(filesDir, FILE)
                val scratch = File(filesDir, "$FILE.new")
                scratch.writeText(text)
                if (!scratch.renameTo(target)) {
                    throw IllegalStateException("anchor rename failed")
                }
            } catch (e: Throwable) {
                throw AnchorException.Unwritable()
            }
        }

        override fun backing(): String = describeBacking()
    }

    private fun ensureKey() {
        // USABLE-NOT-EXISTS: nothing invalidates this key, and recreating it loses the anchor.
        if (!exists()) {
            create()
        }
    }

    private fun create(): SecretKey =
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE).apply {
            init(
                KeyGenParameterSpec.Builder(
                    ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    // No user authentication: the anchor is read on every open.
                    .setIsStrongBoxBacked(true)
                    .build(),
            )
        }.generateKey()

    private fun exists(): Boolean =
        KeyStore.getInstance(KEYSTORE).apply { load(null) }.containsAlias(ALIAS)

    private fun loadKey(): SecretKey {
        val store = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        return (store.getEntry(ALIAS, null) as KeyStore.SecretKeyEntry).secretKey
    }

    private fun describeBacking(): String = try {
        val info = SecretKeyFactory
            .getInstance(loadKey().algorithm, KEYSTORE)
            .getKeySpec(loadKey(), KeyInfo::class.java) as KeyInfo
        when {
            info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX -> "SecureElement"
            info.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ->
                "TrustedExecutionEnvironment"
            else -> "SoftwareOnly"
        }
    } catch (e: Throwable) {
        // Unknown reads as software-only, never as hardware (R1).
        "SoftwareOnly"
    }

    /** Only `forgetDevice` calls this, never an unlock. */
    fun reset(filesDir: File) {
        val store = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        if (store.containsAlias(ALIAS)) {
            store.deleteEntry(ALIAS)
        }
        File(filesDir, FILE).delete()
    }
}
