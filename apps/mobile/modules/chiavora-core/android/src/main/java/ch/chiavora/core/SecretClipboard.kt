package ch.chiavora.core

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** Only the TTL stops another process reading the clip (A4), and nothing recalls a read copy. */
object SecretClipboard {
    data class Applied(
        val ttl: Boolean,
        val sensitiveFlag: Boolean,
    )

    private val scope = CoroutineScope(Dispatchers.Default)
    private var expiry: Job? = null

    @Synchronized
    fun copy(context: Context, label: String, secret: String, ttlSeconds: Int): Applied {
        val manager = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText(label, secret)

        val sensitive = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
        if (sensitive) {
            clip.description.extras = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
        }
        manager.setPrimaryClip(clip)

        // One timer: a newer copy replaces the older deadline.
        expiry?.cancel()
        expiry = scope.launch {
            delay(ttlSeconds * 1000L)
            clearIfStillOurs(manager, secret)
        }
        return Applied(ttl = true, sensitiveFlag = sensitive)
    }

    private fun clearIfStillOurs(manager: ClipboardManager, secret: String) {
        val current = manager.primaryClip
        val held = if (current != null && current.itemCount > 0) {
            current.getItemAt(0).text?.toString()
        } else {
            null
        }
        if (held != secret) {
            // The user has copied something else since.
            return
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            manager.clearPrimaryClip()
        } else {
            manager.setPrimaryClip(ClipData.newPlainText("", ""))
        }
    }
}
