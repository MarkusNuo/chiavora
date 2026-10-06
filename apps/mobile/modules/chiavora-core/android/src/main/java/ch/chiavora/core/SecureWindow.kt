package ch.chiavora.core

import android.app.Activity
import android.view.WindowManager

/** Accessibility services read the view tree and are not stopped by `FLAG_SECURE` (A8). */
object SecureWindow {
    enum class Reason {
        SESSION,
        GENERATED_VALUE,
    }

    private val reasons = mutableSetOf<Reason>()

    @Synchronized
    fun hold(activity: Activity?, reason: Reason) {
        reasons.add(reason)
        apply(activity)
    }

    @Synchronized
    fun release(activity: Activity?, reason: Reason) {
        reasons.remove(reason)
        apply(activity)
    }

    @Synchronized
    fun isSecure(): Boolean = reasons.isNotEmpty()

    @Synchronized
    fun reapply(activity: Activity?) {
        apply(activity)
    }

    private fun apply(activity: Activity?) {
        // With no activity, the reason is still recorded and `reapply` sets the flag later.
        val window = activity?.window ?: return
        // UI-THREAD: window flags belong to the window's thread; only the flag write is hopped.
        activity.runOnUiThread {
            if (reasons.isEmpty()) {
                window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
            } else {
                window.setFlags(
                    WindowManager.LayoutParams.FLAG_SECURE,
                    WindowManager.LayoutParams.FLAG_SECURE,
                )
            }
        }
    }
}
