package ch.chiavora.core

import expo.modules.kotlin.modules.ModuleDefinitionBuilder

/** Imports nothing from the bindings, whose release build has no harness symbol. */
internal fun ModuleDefinitionBuilder.harnessDefinition() {
    Function("hasHarness") { false }
}
