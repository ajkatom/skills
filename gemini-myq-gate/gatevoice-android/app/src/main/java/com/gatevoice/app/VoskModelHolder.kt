package com.gatevoice.app

import android.content.Context
import org.json.JSONObject
import org.vosk.Model
import org.vosk.android.StorageService

/**
 * Loads the bundled offline Vosk model once and caches it. The model lives in
 * assets/model-en-us (placed there at build time — see the CI workflow and
 * README). Everything here is on-device; no network, no cloud.
 */
object VoskModelHolder {
    @Volatile private var model: Model? = null

    fun get(context: Context, onReady: (Model) -> Unit, onError: (Exception) -> Unit) {
        model?.let { onReady(it); return }
        StorageService.unpack(
            context, "model-en-us", "model",
            { m -> model = m; onReady(m) },
            { e -> onError(e) }
        )
    }

    /** Pull the recognized text out of a Vosk JSON hypothesis. */
    fun textOf(json: String?): String {
        if (json.isNullOrBlank()) return ""
        return try {
            val o = JSONObject(json)
            (o.optString("text").ifBlank { o.optString("partial") }).trim()
        } catch (e: Exception) {
            ""
        }
    }
}
