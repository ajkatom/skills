package com.gatevoice.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import org.vosk.Model
import org.vosk.Recognizer
import org.vosk.android.RecognitionListener
import org.vosk.android.SpeechService

/**
 * Always-on, fully offline wake-word listener. Streams the mic through Vosk and
 * watches for the user's custom wake word (default "sesame"). Once heard, it
 * either acts immediately if the same utterance also names a door
 * ("sesame open gate"), or arms for a few seconds to catch the door in the next
 * utterance ("sesame" … "open garage door two").
 */
class VoskWakeService : Service(), RecognitionListener {

    private var speech: SpeechService? = null
    private val handler = Handler(Looper.getMainLooper())
    private var armedUntil = 0L

    override fun onCreate() {
        super.onCreate()
        startForegroundNotice()
        VoskModelHolder.get(this, ::startListening) { e ->
            updateNotice("Voice model error: ${e.message}")
        }
    }

    private fun startListening(model: Model) {
        try {
            val rec = Recognizer(model, 16000.0f)
            speech = SpeechService(rec, 16000.0f).also { it.startListening(this) }
            updateNotice("Listening for \"${Prefs(this).wakeWord}\"")
        } catch (e: Exception) {
            updateNotice("Mic error: ${e.message}")
        }
    }

    override fun onPartialResult(hypothesis: String?) {
        // Wake word can be caught on a partial for faster response.
        val text = VoskModelHolder.textOf(hypothesis)
        if (text.isNotBlank()) consider(text, partial = true)
    }

    override fun onResult(hypothesis: String?) {
        val text = VoskModelHolder.textOf(hypothesis)
        if (text.isNotBlank()) consider(text, partial = false)
    }

    override fun onFinalResult(hypothesis: String?) {}
    override fun onError(e: Exception?) { updateNotice("Error: ${e?.message}") }
    override fun onTimeout() {}

    private fun consider(text: String, partial: Boolean) {
        val prefs = Prefs(this)
        val wake = prefs.wakeWord
        val hasWake = text.contains(wake, ignoreCase = true)
        val now = System.currentTimeMillis()

        if (hasWake) {
            // Try the whole utterance first (wake + command together).
            val tile = CommandParser.parse(text, prefs.gateTile, prefs.doorsMap())
            if (tile != null && !partial) {
                act(tile)
                return
            }
            // Otherwise arm and wait for the command in the next utterance.
            armedUntil = now + 6000
            updateNotice("Heard \"$wake\" — say the door")
            return
        }

        // Already armed by a prior wake word: treat this as the command.
        if (now < armedUntil && !partial) {
            val tile = CommandParser.parse(text, prefs.gateTile, prefs.doorsMap())
            if (tile != null) {
                armedUntil = 0L
                act(tile)
            }
        }
    }

    private fun act(tile: String) {
        handler.post {
            GateController.openTile(this, tile)
            updateNotice("Opening $tile…")
            handler.postDelayed(
                { updateNotice("Listening for \"${Prefs(this).wakeWord}\"") }, 4000
            )
        }
    }

    override fun onDestroy() {
        speech?.stop()
        speech?.shutdown()
        speech = null
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    // --- foreground notification -------------------------------------------
    private fun startForegroundNotice() {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(CH, "GateVoice", NotificationManager.IMPORTANCE_LOW)
            )
        }
        startForeground(1, notice("Starting…"))
    }

    private fun notice(text: String): Notification =
        Notification.Builder(this, CH)
            .setContentTitle("GateVoice")
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_launcher)
            .setOngoing(true)
            .build()

    private fun updateNotice(text: String) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(1, notice(text))
    }

    companion object {
        private const val CH = "gatevoice"
        fun start(context: Context) {
            val i = Intent(context, VoskWakeService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) context.startForegroundService(i)
            else context.startService(i)
        }
        fun stop(context: Context) {
            context.stopService(Intent(context, VoskWakeService::class.java))
        }
    }
}
