package com.gatevoice.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Restart the keep-alive service after a reboot so shortcut/voice taps work
 *  without opening the app first. Best-effort (background FGS start may be
 *  limited; opening the app once re-establishes it). */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action == Intent.ACTION_BOOT_COMPLETED) {
            KeepAliveService.start(context)
        }
    }
}
