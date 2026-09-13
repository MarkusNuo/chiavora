package ch.chiavora.core
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import uniffi.chiavora_ffi_mobile.ffiSmoke

/** Every function returns what the UI needs to render, never key material. */
class ChiavoraCoreModule : Module() {

    override fun definition() = ModuleDefinition {
        Name("ChiavoraCore")

        Function("ffiSmoke") {
            ffiSmoke()
        }

        // One copy per build variant; only the debug one registers the measurement harness.
        harnessDefinition()
    }
}
