package com.gatevoice.app

import android.content.Context
import android.widget.Toast

/**
 * The heart of "one smart command": given recognized speech, decide the tile,
 * launch myQ, and arm the accessibility service to tap it.
 */
object GateController {

    /** @return the tile it will open, or null if the phrase wasn't understood. */
    fun handlePhrase(context: Context, phrase: String?): String? {
        val prefs = Prefs(context)
        val tile = CommandParser.parse(phrase, prefs.gateTile, prefs.doorsMap())
        if (tile == null) {
            toast(context, "Didn't catch which door: \"${phrase ?: ""}\"")
            PendingTap.clear("unrecognized: \"${phrase ?: ""}\"")
            return null
        }
        openTile(context, tile)
        return tile
    }

    /** Directly open a known tile (used by the app's test buttons). */
    fun openTile(context: Context, tile: String) {
        val prefs = Prefs(context)
        PendingTap.request(tile, prefs.tapWindowMs)

        val launch = context.packageManager.getLaunchIntentForPackage(prefs.myqPackage)
        if (launch == null) {
            toast(context, "myQ app not found (${prefs.myqPackage})")
            PendingTap.clear("myQ package not installed")
            return
        }
        launch.addFlags(
            android.content.Intent.FLAG_ACTIVITY_NEW_TASK or
                android.content.Intent.FLAG_ACTIVITY_REORDER_TO_FRONT
        )
        context.startActivity(launch)
        toast(context, "Opening $tile…")
        // The MyqAccessibilityService will click the tile when myQ appears.
    }

    private fun toast(context: Context, msg: String) {
        Toast.makeText(context.applicationContext, msg, Toast.LENGTH_SHORT).show()
    }
}
