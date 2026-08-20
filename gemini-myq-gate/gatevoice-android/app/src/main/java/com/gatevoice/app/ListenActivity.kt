package com.gatevoice.app

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import org.vosk.Model
import org.vosk.Recognizer
import org.vosk.android.RecognitionListener
import org.vosk.android.SpeechService

/**
 * One-tap path: launched by the Quick Settings tile, the home-screen widget,
 * or "open GateVoice listen". Listens for a single spoken door name (no wake
 * word needed here — the tap IS the trigger), parses it, opens the door.
 */
class ListenActivity : AppCompatActivity(), RecognitionListener {

    private var speech: SpeechService? = null
    private val handler = Handler(Looper.getMainLooper())
    private var done = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO)
            != PackageManager.PERMISSION_GRANTED
        ) {
            Toast.makeText(this, "Grant Microphone to GateVoice first", Toast.LENGTH_LONG).show()
            finish(); return
        }
        Toast.makeText(this, "Listening — say the door…", Toast.LENGTH_SHORT).show()
        VoskModelHolder.get(this, ::listen) { e ->
            Toast.makeText(this, "Voice model error: ${e.message}", Toast.LENGTH_LONG).show()
            finish()
        }
        // Safety timeout.
        handler.postDelayed({ if (!done) finishUp(null) }, 7000)
    }

    private fun listen(model: Model) {
        try {
            val rec = Recognizer(model, 16000.0f)
            speech = SpeechService(rec, 16000.0f).also { it.startListening(this) }
        } catch (e: Exception) {
            Toast.makeText(this, "Mic error: ${e.message}", Toast.LENGTH_LONG).show()
            finish()
        }
    }

    override fun onResult(hypothesis: String?) {
        val text = VoskModelHolder.textOf(hypothesis)
        if (text.isNotBlank()) finishUp(text)
    }

    override fun onFinalResult(hypothesis: String?) {
        val text = VoskModelHolder.textOf(hypothesis)
        if (!done && text.isNotBlank()) finishUp(text)
    }

    override fun onPartialResult(hypothesis: String?) {}
    override fun onError(e: Exception?) { finishUp(null) }
    override fun onTimeout() { finishUp(null) }

    private fun finishUp(text: String?) {
        if (done) return
        done = true
        speech?.stop(); speech?.shutdown(); speech = null
        if (text != null) GateController.handlePhrase(this, text)
        finish()
    }

    override fun onDestroy() {
        speech?.shutdown(); speech = null
        super.onDestroy()
    }
}
