package com.gatevoice.app

import android.content.Context
import android.provider.Settings
import android.text.TextUtils
import android.widget.Toast

/**
 * The heart of "one smart command": given recognized speech, decide the
 * device(s), launch myQ, and arm the accessibility service to tap them.
 */
object GateController {

    /** @return the tiles it will open (may be several), or empty if not understood. */
    fun handlePhrase(context: Context, phrase: String?): List<String> {
        val prefs = Prefs(context)
        val tiles = CommandParser.parseAll(phrase, prefs.gateTile, prefs.doorsMap())
        if (tiles.isEmpty()) {
            toast(context, "Didn't catch a device: \"${phrase ?: ""}\"")
            PendingTap.clear("unrecognized: \"${phrase ?: ""}\"")
            return emptyList()
        }
        openTiles(context, tiles)
        return tiles
    }

    /** Open one known tile (used by the app's per-door test buttons). */
    fun openTile(context: Context, tile: String) = openTiles(context, listOf(tile))

    /** Open several tiles in sequence with one myQ launch. */
    fun openTiles(context: Context, tiles: List<String>) {
        val prefs = Prefs(context)
        if (!isAccessibilityEnabled(context)) {
            toast(context, "Enable GateVoice in Accessibility settings first")
            PendingTap.clear("accessibility service is OFF — enable it, then retry")
            return
        }
        PendingTap.request(tiles, prefs.tapWindowMs)

        val launch = context.packageManager.getLaunchIntentForPackage(prefs.myqPackage)
        if (launch == null) {
            toast(context, "myQ app not found (${prefs.myqPackage})")
            PendingTap.clear("myQ package not installed: ${prefs.myqPackage}")
            return
        }
        launch.addFlags(
            android.content.Intent.FLAG_ACTIVITY_NEW_TASK or
                android.content.Intent.FLAG_ACTIVITY_REORDER_TO_FRONT
        )
        context.startActivity(launch)
        toast(context, "Opening ${tiles.joinToString(", ")}…")
    }

    /** True if our accessibility service is enabled in system settings. */
    fun isAccessibilityEnabled(context: Context): Boolean {
        val expected = context.packageName + "/" + MyqAccessibilityService::class.java.name
        val flat = Settings.Secure.getString(
            context.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
        ) ?: return false
        val splitter = TextUtils.SimpleStringSplitter(':')
        splitter.setString(flat)
        for (name in splitter) {
            if (name.equals(expected, ignoreCase = true)) return true
        }
        return false
    }

    private fun toast(context: Context, msg: String) {
        Toast.makeText(context.applicationContext, msg, Toast.LENGTH_SHORT).show()
    }
}
