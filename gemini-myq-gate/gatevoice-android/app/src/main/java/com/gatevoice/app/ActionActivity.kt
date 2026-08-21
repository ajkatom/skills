package com.gatevoice.app

import android.app.Activity
import android.os.Bundle

/**
 * Mic-free trigger. Launched by an app shortcut (which Google Assistant can
 * fire from "Hey Google, open the gate"), or by a gatevoice://act deep link.
 * Reads the device + action, kicks GateController, and finishes immediately —
 * no microphone, so it never conflicts with "Hey Google".
 *
 * Shortcut intent extras:  device="Garage Door 2", action="open"|"close"|"toggle"
 * Deep link:               gatevoice://act?device=Garage%20Door%202&action=open
 */
class ActionActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        KeepAliveService.start(this)   // ensure we stay alive for future cold triggers
        val device = intent.getStringExtra("device")
            ?: intent.data?.getQueryParameter("device")
        val actionStr = (intent.getStringExtra("action")
            ?: intent.data?.getQueryParameter("action") ?: "open").lowercase()
        if (!device.isNullOrBlank()) {
            val action = when (actionStr) {
                "close" -> GateAction.CLOSE
                "toggle" -> GateAction.TOGGLE
                else -> GateAction.OPEN
            }
            GateController.openTile(this, device, action)
        }
        finish()
    }
}
