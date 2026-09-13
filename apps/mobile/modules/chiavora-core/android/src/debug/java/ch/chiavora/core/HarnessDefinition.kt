package ch.chiavora.core
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

    /** Synchronous because it never calls into `core`. */
    Function("hasHarness") { true }
}
