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

    /** @return the tiles it will act on (may be several), or empty if not understood. */
    fun handlePhrase(context: Context, phrase: String?): List<String> {
        val prefs = Prefs(context)
        val tiles = CommandParser.parseAll(phrase, prefs.gateTile, prefs.doorsMap())
        if (tiles.isEmpty()) {
            toast(context, "Didn't catch a device: \"${phrase ?: ""}\"")
            PendingTap.clear("unrecognized: \"${phrase ?: ""}\"")
            return emptyList()
        }
        openTiles(context, tiles, CommandParser.detectAction(phrase))
        return tiles
    }

    /** Act on one known tile (used by the app's per-door test buttons). */
    fun openTile(context: Context, tile: String, action: GateAction = GateAction.OPEN) =
        openTiles(context, listOf(tile), action)

    /** Act on several tiles in sequence with one myQ launch. */
    fun openTiles(context: Context, tiles: List<String>, action: GateAction = GateAction.OPEN) {
        val prefs = Prefs(context)
        if (!isAccessibilityEnabled(context)) {
            toast(context, "Enable GateVoice in Accessibility settings first")
            PendingTap.clear("accessibility service is OFF — enable it, then retry")
            return
        }
        // At least 20s so there's ample time while myQ is foreground.
        PendingTap.request(tiles, maxOf(prefs.tapWindowMs, 20_000L), action)

        val launch = context.packageManager.getLaunchIntentForPackage(prefs.myqPackage)
        if (launch == null) {
            toast(context, "myQ app not found (${prefs.myqPackage})")
            PendingTap.clear("myQ package not installed: ${prefs.myqPackage}")
            return
        }
        // NEW_TASK only — REORDER_TO_FRONT caused focus to bounce back to us.
        launch.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(launch)
        val verb = when (action) {
            GateAction.OPEN -> "Opening"; GateAction.CLOSE -> "Closing"; GateAction.TOGGLE -> "Toggling"
        }
        toast(context, "$verb ${tiles.joinToString(", ")}…")

        // Proactively start the tap loop — don't depend on an accessibility
        // event firing when myQ comes to the front. Kick it a few times as myQ
        // loads; scheduleAttempts is idempotent and only acts once myQ is shown.
        val h = android.os.Handler(android.os.Looper.getMainLooper())
        for (delay in listOf(400L, 900L, 1800L, 3000L, 5000L)) {
            h.postDelayed({
                val svc = MyqAccessibilityService.instance
                if (svc == null) {
                    PendingTap.lastStatus = "kick@${delay}ms: accessibility service NOT connected"
                } else {
                    svc.beginTapNow()
                }
            }, delay)
        }
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
