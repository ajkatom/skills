package com.gatevoice.companion

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.Toast

/**
 * One-shot launcher. On open (by tap or "Hey Google, launch GateVoice Front"),
 * it fires the gatevoice:// deep link for its configured device+action, which
 * GateVoice's ActionActivity handles and taps myQ. No UI, no mic, no
 * accessibility of its own — it just delegates to the installed GateVoice app.
 */
class CompanionActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val uri = Uri.parse(
            "gatevoice://act?device=" + Uri.encode(BuildConfig.DEVICE) +
                "&action=" + Uri.encode(BuildConfig.GVACTION)
        )
        val intent = Intent(Intent.ACTION_VIEW, uri)
            .setPackage("com.gatevoice.app")
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        try {
            startActivity(intent)
        } catch (e: Exception) {
            Toast.makeText(this, "Install/enable GateVoice first", Toast.LENGTH_LONG).show()
        }
        finish()
    }
}
