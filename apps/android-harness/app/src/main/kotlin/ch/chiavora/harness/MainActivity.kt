package ch.chiavora.harness

import android.app.Activity
import android.app.ActivityManager
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.widget.ScrollView
import android.widget.TextView
import kotlin.concurrent.thread
import uniffi.chiavora_ffi_mobile.DerivationOutcome
import uniffi.chiavora_ffi_mobile.harnessDeriveOnce

/**
 * The Argon2id derivation inside a real app, to measure whether a backgrounded app may hold
 * 256 MiB. A run is driven by the launch intent, for example `am start -n
 * ch.chiavora.harness/.MainActivity --ei memory_kib 262144 --ei iterations 4 --ei delay_ms 8000
 * --es label bg`; the delay leaves time to press HOME, so the derivation starts in a cached
 * process, and `oom_score_adj` is recorded before and after as evidence. No key material is logged.
 */
class MainActivity : Activity() {

    private lateinit var output: TextView
    private val lines = StringBuilder()

    @Volatile
    private var stopped = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        output = TextView(this).apply { setPadding(24, 24, 24, 24) }
        setContentView(ScrollView(this).apply { addView(output) })

        val memoryKib = intent.getIntExtra("memory_kib", DEFAULT_MEMORY_KIB)
        val iterations = intent.getIntExtra("iterations", DEFAULT_ITERATIONS)
        val delayMs = intent.getLongExtra("delay_ms", 0L)
        val label = intent.getStringExtra("label") ?: "unlabelled"

        say("run '$label': m=${memoryKib / 1024} MiB t=$iterations, starting in ${delayMs} ms")

        // A plain thread, so no scheduler decides when the derivation runs.
        thread(name = "harness-derive") {
            if (delayMs > 0) {
                Thread.sleep(delayMs)
            }
            runDerivation(label, memoryKib, iterations)
        }
    }

    private fun runDerivation(label: String, memoryKib: Int, iterations: Int) {
        val importance = myImportance()
        val stoppedAtStart = stopped
        say("run '$label': starting, activity stopped=$stoppedAtStart, importance=${importanceName(importance)}")

        val outcome: DerivationOutcome = try {
            harnessDeriveOnce(memoryKib.toUInt(), iterations.toUInt())
        } catch (e: Exception) {
            say("run '$label': HARNESS ERROR ${e}")
            return
        }

        // One machine-readable line per run.
        Log.i(
            TAG,
            "RESULT label=$label completed=${outcome.completed} millis=${outcome.millis}" +
                " refusal=${outcome.refusal ?: "-"}" +
                " oom_before=${outcome.oomScoreAdjBefore ?: "-"}" +
                " oom_after=${outcome.oomScoreAdjAfter ?: "-"}" +
                " mem_avail_kib_before=${outcome.memAvailableKibBefore ?: "-"}" +
                " mem_avail_kib_after=${outcome.memAvailableKibAfter ?: "-"}" +
                " m_kib=${outcome.memoryKib} t=${outcome.iterations}" +
                " stopped_at_start=$stoppedAtStart importance=${importanceName(importance)}" +
                " importance_at_end=${importanceName(myImportance())}"
        )

        say(
            if (outcome.completed) {
                "run '$label': COMPLETED in ${outcome.millis} ms, oom_score_adj ${outcome.oomScoreAdjBefore} -> ${outcome.oomScoreAdjAfter}"
            } else {
                "run '$label': REFUSED (${outcome.refusal}) after ${outcome.millis} ms"
            }
        )
    }

    override fun onStart() {
        super.onStart()
        stopped = false
        Log.i(TAG, "LIFECYCLE onStart importance=${importanceName(myImportance())}")
    }

    override fun onStop() {
        super.onStop()
        stopped = true
        Log.i(TAG, "LIFECYCLE onStop importance=${importanceName(myImportance())}")
    }

    private fun myImportance(): Int {
        val state = ActivityManager.RunningAppProcessInfo()
        ActivityManager.getMyMemoryState(state)
        return state.importance
    }

    private fun importanceName(importance: Int): String = when (importance) {
        ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND -> "FOREGROUND($importance)"
        ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND_SERVICE -> "FOREGROUND_SERVICE($importance)"
        ActivityManager.RunningAppProcessInfo.IMPORTANCE_VISIBLE -> "VISIBLE($importance)"
        ActivityManager.RunningAppProcessInfo.IMPORTANCE_PERCEPTIBLE -> "PERCEPTIBLE($importance)"
        ActivityManager.RunningAppProcessInfo.IMPORTANCE_SERVICE -> "SERVICE($importance)"
        ActivityManager.RunningAppProcessInfo.IMPORTANCE_CACHED -> "CACHED($importance)"
        ActivityManager.RunningAppProcessInfo.IMPORTANCE_GONE -> "GONE($importance)"
        else -> "OTHER($importance)"
    }

    private fun say(line: String) {
        Log.i(TAG, line)
        lines.append(line).append('\n')
        Handler(Looper.getMainLooper()).post {
            if (::output.isInitialized) {
                output.text = lines.toString()
            }
        }
    }

    private companion object {
        init {
            // Loaded early, so a missing or wrong-ABI library fails here and not mid-measurement.
            System.loadLibrary("chiavora_ffi_mobile")
        }

        const val TAG = "CHIAVORA-HARNESS"

        /** §2.1's measured parameters: m = 256 MiB. */
        const val DEFAULT_MEMORY_KIB = 256 * 1024

        /** §2.1's measured parameters: t = 4. */
        const val DEFAULT_ITERATIONS = 4
    }
}
