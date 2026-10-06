package ch.chiavora.core

import android.app.Activity
import android.view.MotionEvent
import android.view.Window
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** The idle deadline may run late on a dozing device, never early. */
class LockController(
    private val scope: CoroutineScope = CoroutineScope(Dispatchers.Default),
    private val onLock: (LockReason) -> Unit,
) {
    enum class LockReason {
        MANUAL,
        BACKGROUNDED,
        IDLE,
    }

    @Volatile
    private var idleTimeoutMillis: Long = 0

    @Volatile
    private var armed: Boolean = false

    private var countdown: Job? = null

    private val lifecycleObserver = object : DefaultLifecycleObserver {
        override fun onStop(owner: LifecycleOwner) {
            // The whole process, not one activity, so a rotation does not lock.
            if (armed) {
                fire(LockReason.BACKGROUNDED)
            }
        }
    }

    fun arm(idleTimeoutMillis: Long) {
        this.idleTimeoutMillis = idleTimeoutMillis
        if (!armed) {
            armed = true
            ProcessLifecycleOwner.get().lifecycle.addObserver(lifecycleObserver)
        }
        restartCountdown()
    }

    fun disarm() {
        armed = false
        countdown?.cancel()
        countdown = null
        ProcessLifecycleOwner.get().lifecycle.removeObserver(lifecycleObserver)
    }

    fun lockNow() {
        if (armed) {
            fire(LockReason.MANUAL)
        }
    }

    fun watchTouches(activity: Activity) {
        val existing = activity.window.callback
        if (existing is TouchObserver) {
            return
        }
        activity.window.callback = TouchObserver(existing) { restartCountdown() }
    }

    private fun restartCountdown() {
        countdown?.cancel()
        if (!armed || idleTimeoutMillis <= 0) {
            return
        }
        countdown = scope.launch {
            delay(idleTimeoutMillis)
            // `disarm` may have run while this was suspended.
            if (armed) {
                fire(LockReason.IDLE)
            }
        }
    }

    private fun fire(reason: LockReason) {
        disarm()
        onLock(reason)
    }

    private class TouchObserver(
        private val inner: Window.Callback,
        private val onTouch: () -> Unit,
    ) : Window.Callback by inner {
        override fun dispatchTouchEvent(event: MotionEvent): Boolean {
            onTouch()
            return inner.dispatchTouchEvent(event)
        }
    }
}
