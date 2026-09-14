package ch.chiavora.core

import java.nio.ByteBuffer
import expo.modules.kotlin.modules.ModuleDefinitionBuilder
import uniffi.chiavora_ffi_mobile.harnessDeriveOnce

/** Debug builds only; release builds get the copy in `src/release`. */
internal fun ModuleDefinitionBuilder.harnessDefinition() {
    /** Slept here, on the deriving thread, because JavaScript timers stop in the background. */
    AsyncFunction("harnessDeriveOnce") { memoryKib: Int, iterations: Int, delayMs: Int ->
        if (delayMs > 0) {
            Thread.sleep(delayMs.toLong())
        }
        val outcome = harnessDeriveOnce(memoryKib.toUInt(), iterations.toUInt())
        mapOf(
            "completed" to outcome.completed,
            "millis" to outcome.millis.toLong(),
            "refusal" to outcome.refusal,
            "oomScoreAdjBefore" to outcome.oomScoreAdjBefore,
            "oomScoreAdjAfter" to outcome.oomScoreAdjAfter,
            "memAvailableKibBefore" to outcome.memAvailableKibBefore?.toLong(),
            "memAvailableKibAfter" to outcome.memAvailableKibAfter?.toLong(),
            "memoryKib" to outcome.memoryKib.toLong(),
            "iterations" to outcome.iterations.toLong(),
        )
    }

    /** Decides whether an off-heap path could avoid the `byte[]` copy of the MUK. */
    AsyncFunction("keystoreProviderReport") {
        keystoreProviderReport()
    }

    /** Synchronous because it never calls into `core`. */
    Function("hasHarness") { true }
}

private const val CIPHER_SPI = "javax.crypto.CipherSpi"

private fun declaringClassOf(spi: Any, name: String, vararg types: Class<*>): String? {
    var here: Class<*>? = spi.javaClass
    while (here != null) {
        try {
            here.getDeclaredMethod(name, *types)
            return here.name
        } catch (_: NoSuchMethodException) {
            here = here.superclass
        }
    }
    return null
}

private fun keystoreProviderReport(): Map<String, Any?> {
    val provider = java.security.Security.getProvider("AndroidKeyStore")
        ?: return mapOf("error" to "no AndroidKeyStore provider on this device")
    val service = provider.getService("Cipher", "AES/GCM/NoPadding")
        ?: return mapOf("error" to "AndroidKeyStore has no AES/GCM/NoPadding Cipher service")

    val spi = try {
        service.newInstance(null)
    } catch (e: Throwable) {
        // The class name only: a provider's message can name aliases (I1).
        return mapOf("error" to "newInstance threw ${e.javaClass.name}")
    } ?: return mapOf("error" to "newInstance returned null")

    val chain = buildList {
        var here: Class<*>? = spi.javaClass
        while (here != null) {
            add(here.name)
            here = here.superclass
        }
    }

    val byteBufferDecl =
        declaringClassOf(spi, "engineDoFinal", ByteBuffer::class.java, ByteBuffer::class.java)
    // The control: the provider overrides this one, as every unlock goes through it.
    val byteArrayDecl = declaringClassOf(
        spi,
        "engineDoFinal",
        ByteArray::class.java,
        Int::class.javaPrimitiveType!!,
        Int::class.javaPrimitiveType!!,
    )

    val controlWorked = byteArrayDecl != null && byteArrayDecl != CIPHER_SPI
    return mapOf(
        "spiClass" to spi.javaClass.name,
        "chain" to chain.joinToString(" <- "),
        "byteBufferDoFinalDeclaredBy" to byteBufferDecl,
        "byteArrayDoFinalDeclaredBy" to byteArrayDecl,
        "controlWorked" to controlWorked,
        "verdict" to when {
            !controlWorked ->
                "INCONCLUSIVE: reflection did not reach the provider's own classes, so " +
                    "'not overridden' cannot be told from 'could not look'"
            byteBufferDecl == null || byteBufferDecl == CIPHER_SPI ->
                "COPIES: the provider inherits javax.crypto.CipherSpi's default, which " +
                    "copies through a byte[]. A direct-ByteBuffer path buys nothing."
            else ->
                "OVERRIDES: declared by $byteBufferDecl — a direct-ByteBuffer path is a " +
                    "real choice, and its cost is a JNI layer in the component holding the MUK"
        },
    )
}
