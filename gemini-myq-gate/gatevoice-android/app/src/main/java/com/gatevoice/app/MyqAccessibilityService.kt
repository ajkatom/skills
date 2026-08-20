package com.gatevoice.app

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.GestureDescription
import android.graphics.Path
import android.graphics.Rect
import android.os.Handler
import android.os.Looper
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo

/**
 * Presses the target tile(s) inside the myQ app. When [PendingTap] is armed and
 * a myQ window appears, it searches the view tree for a node whose text or
 * content-description matches the tile, clicks the nearest clickable ancestor,
 * and (if that fails) taps the tile's on-screen location. Handles a QUEUE so
 * one command can open several devices. Also serves [Diag] screen captures.
 */
class MyqAccessibilityService : AccessibilityService() {

    private val handler = Handler(Looper.getMainLooper())
    private var retryScheduled = false

    override fun onServiceConnected() {
        super.onServiceConnected()
        instance = this
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        val pkg = Prefs(this).myqPackage
        // Diagnostic capture only for myQ windows.
        if (event?.packageName?.toString() == pkg && Diag.active()) captureNow()
        // Start the tap loop on ANY event while a tap is pending; tryTap itself
        // only acts once myQ is the foreground window (it looks for the card).
        if (PendingTap.active()) scheduleAttempts()
    }

    override fun onInterrupt() {}

    override fun onUnbind(intent: android.content.Intent?): Boolean {
        instance = null
        return super.onUnbind(intent)
    }

    /** Called by GateController right after launching myQ, so the tap loop
     *  starts even if no accessibility event happens to fire. */
    fun beginTapNow() = scheduleAttempts()

    companion object {
        @Volatile
        var instance: MyqAccessibilityService? = null
    }

    private fun scheduleAttempts() {
        if (retryScheduled) return
        retryScheduled = true
        PendingTap.lastStatus = "polling for myQ…"
        var attempts = 0
        val pkg = Prefs(this).myqPackage
        val tick = object : Runnable {
            override fun run() {
                if (!PendingTap.active()) { retryScheduled = false; return }
                val target = PendingTap.current()
                // Search ALL of myQ's windows, not just rootInActiveWindow —
                // on One UI the device list can live in a window that isn't the
                // "active" one, which is why sawDoor stayed false.
                val roots = myqWindowRoots(pkg)
                val myQShown = roots.isNotEmpty()
                if (myQShown) PendingTap.sawMyQ = true

                if (myQShown && target != null && tryTapInRoots(roots, target)) {
                    PendingTap.completeCurrent()
                    val next = PendingTap.current()
                    if (next == null) { retryScheduled = false; return }
                    PendingTap.lastStatus = "opened $target, now $next"
                    attempts = 0
                    handler.postDelayed(this, 1600)
                    return
                }
                attempts++
                val marks = "[sawMyQ=${PendingTap.sawMyQ} sawDoor=${PendingTap.sawNode}]"
                PendingTap.lastStatus = if (myQShown)
                    "poll $attempts: myQ shown, searching \"$target\" $marks"
                else
                    "poll $attempts: myQ not visible (fg=${rootInActiveWindow?.packageName}) $marks"
                if (System.currentTimeMillis() < PendingTap.expiresAt && attempts < 120) {
                    handler.postDelayed(this, 300)
                } else {
                    PendingTap.clear(failureStatus(target))
                    retryScheduled = false
                }
            }
        }
        handler.post(tick)
    }

    /** All root nodes of windows that belong to myQ (handles multi-window). */
    private fun myqWindowRoots(pkg: String): List<AccessibilityNodeInfo> {
        val roots = ArrayList<AccessibilityNodeInfo>()
        try {
            for (w in windows) {
                val r = try { w.root } catch (e: Exception) { null } ?: continue
                if (r.packageName?.toString() == pkg) roots.add(r)
            }
        } catch (e: Exception) { /* windows may be unavailable briefly */ }
        if (roots.isEmpty()) {
            rootInActiveWindow?.let { if (it.packageName?.toString() == pkg) roots.add(it) }
        }
        return roots
    }

    /** Find the door in any myQ window and tap it. */
    private fun tryTapInRoots(roots: List<AccessibilityNodeInfo>, tileText: String): Boolean {
        for (root in roots) {
            val nameNode = findExactText(root, tileText) ?: continue
            PendingTap.sawNode = true
            if (tapCard(nameNode, tileText)) return true
        }
        return false
    }

    private fun tapCard(nameNode: AccessibilityNodeInfo, tileText: String): Boolean {
        val card = nearestClickable(nameNode) ?: nameNode
        val action = PendingTap.action

        // myQ shows each device as a card: name + status ("Open for.."/"Closed
        // for..") + a round open/close control (desc="device state icon"). The
        // card is clickable but only opens the detail view; the round control
        // is what actually opens/closes — and myQ does NOT expose it as
        // click-actionable, so we tap its screen location directly.
        val statusText = collectLabels(card, mutableListOf(), 0).joinToString(" ").lowercase()
        val isOpen = statusText.contains("open for") || statusText.contains("opening")
        val isClosed = statusText.contains("closed for") || statusText.contains("closing")

        // Only act when the door is in the OPPOSITE state (the icon is a toggle).
        when (action) {
            GateAction.OPEN -> if (isOpen) {
                PendingTap.lastStatus = "\"$tileText\" is already open — left as is"; return true
            }
            GateAction.CLOSE -> if (isClosed) {
                PendingTap.lastStatus = "\"$tileText\" is already closed — left as is"; return true
            }
            GateAction.TOGGLE -> {}  // always tap
        }

        // The WHOLE card is the open/close button; the round "device state
        // icon" is only a status readout. A real gesture tap on the card
        // toggles the door. (ACTION_CLICK on the card instead opens myQ's
        // detail view, and tapping the status icon does nothing — that's why
        // earlier builds failed.)
        val r = Rect(); card.getBoundsInScreen(r)
        if (r.width() > 0 && r.height() > 0) {
            val tapX = r.left + r.width() * 0.30f   // text area, clear of the status icon
            val tapY = r.exactCenterY()
            tapAt(tapX, tapY)
            PendingTap.lastStatus = "tapped ${action.name.lowercase()} card for \"$tileText\" — verifying…"
            safeConfirm(action)
            verifyChange(tileText, statusText, action)
            return true
        }
        return false
    }

    /** 2.5s after a tap, re-read the same card and report whether the state
     *  actually changed — so we never claim success when the door didn't move
     *  (which tells us the round "device state icon" isn't the real control). */
    private fun verifyChange(tileText: String, before: String, action: GateAction) {
        handler.postDelayed({
            val r = rootInActiveWindow ?: return@postDelayed
            val n = findExactText(r, tileText) ?: run {
                PendingTap.lastStatus = "tapped \"$tileText\" (left myQ before I could verify)"
                return@postDelayed
            }
            val card = nearestClickable(n) ?: n
            val after = collectLabels(card, mutableListOf(), 0).joinToString(" ").lowercase()
            PendingTap.lastStatus = if (after.trim() != before.trim()) {
                "OK: \"$tileText\" ${action.name.lowercase()} worked — now \"${after.take(60)}\""
            } else {
                "FAILED: \"$tileText\" did NOT change after tap — the round icon is not the " +
                    "control. Capture the device DETAIL screen so I can target the real button."
            }
        }, 2500)
    }

    /** Node whose text/desc EXACTLY equals the tile name (case-insensitive). */
    private fun findExactText(root: AccessibilityNodeInfo, text: String): AccessibilityNodeInfo? {
        val matches = root.findAccessibilityNodeInfosByText(text)
        return matches.firstOrNull { it.text?.toString().equals(text, ignoreCase = true) }
            ?: matches.firstOrNull { it.contentDescription?.toString().equals(text, ignoreCase = true) }
    }

    /** myQ often shows a confirmation dialog (especially when CLOSING a garage
     *  door). Click only an EXACT, clickable label — exact matching keeps the
     *  status text ("Open for 24 minutes"/"Closed for 1 day") from ever being
     *  mistaken for a button. */
    private fun safeConfirm(action: GateAction) {
        val labels = when (action) {
            GateAction.OPEN -> listOf("Confirm", "Yes", "Open")
            GateAction.CLOSE -> listOf("Confirm", "Yes", "Close")
            GateAction.TOGGLE -> listOf("Confirm", "Yes", "Open", "Close")
        }
        handler.postDelayed({
            val r = rootInActiveWindow ?: return@postDelayed
            for (label in labels) {
                val n = r.findAccessibilityNodeInfosByText(label)
                    .firstOrNull { it.text?.toString().equals(label, ignoreCase = true) } ?: continue
                (if (n.isClickable) n else nearestClickable(n))
                    ?.performAction(AccessibilityNodeInfo.ACTION_CLICK)
                break
            }
        }, 800)
    }

    /** Build a status that reveals what myQ actually exposed, so we can tune. */
    private fun failureStatus(target: String?): String {
        val marks = "[sawMyQ=${PendingTap.sawMyQ} sawDoor=${PendingTap.sawNode}]"
        if (!PendingTap.sawMyQ) {
            return "gave up on \"$target\" $marks — myQ never came to the foreground during " +
                "the window. In real use don't switch away from myQ; for this test stay on myQ."
        }
        if (!PendingTap.sawNode) {
            val labels = ArrayList<String>()
            for (root in myqWindowRoots(Prefs(this).myqPackage)) collectLabels(root, labels, 0)
            val shown = labels.distinct().take(20)
            return "gave up on \"$target\" $marks — myQ was shown but the door name wasn't found. " +
                if (shown.isEmpty()) "No readable labels now." else "Last labels: " + shown.joinToString(" | ")
        }
        return "gave up on \"$target\" $marks — found the door but the tap didn't complete."
    }

    private fun captureNow() {
        val pkg = Prefs(this).myqPackage
        val roots = myqWindowRoots(pkg)
        if (roots.isEmpty()) {
            Diag.store("CAPTURE: no myQ windows readable — myQ may block accessibility, " +
                "or the service isn't reading this window.")
            return
        }
        val sb = StringBuilder("CAPTURE of $pkg (${roots.size} window(s))\n")
        roots.forEachIndexed { i, root ->
            sb.append("--- window $i ---\n")
            dumpTree(root, sb, 0)
        }
        Diag.store(sb.toString())
    }

    private fun dumpTree(node: AccessibilityNodeInfo?, sb: StringBuilder, depth: Int) {
        node ?: return
        val text = node.text?.toString()
        val desc = node.contentDescription?.toString()
        if (!text.isNullOrBlank() || !desc.isNullOrBlank() || node.isClickable) {
            val rect = Rect(); node.getBoundsInScreen(rect)
            sb.append("  ".repeat(depth))
                .append(node.className?.toString()?.substringAfterLast('.') ?: "?")
                .append(if (node.isClickable) " [click]" else "")
                .append(if (!text.isNullOrBlank()) " text=\"$text\"" else "")
                .append(if (!desc.isNullOrBlank()) " desc=\"$desc\"" else "")
                .append(" @$rect\n")
        }
        for (i in 0 until node.childCount) dumpTree(node.getChild(i), sb, depth + 1)
    }

    private fun collectLabels(
        node: AccessibilityNodeInfo?, out: MutableList<String>, depth: Int
    ): List<String> {
        node ?: return out
        node.text?.toString()?.takeIf { it.isNotBlank() }?.let { out.add(it) }
        node.contentDescription?.toString()?.takeIf { it.isNotBlank() }?.let { out.add(it) }
        for (i in 0 until node.childCount) collectLabels(node.getChild(i), out, depth + 1)
        return out
    }

    private fun findByDesc(node: AccessibilityNodeInfo?, text: String): AccessibilityNodeInfo? {
        node ?: return null
        val d = node.contentDescription?.toString()
        if (d != null && d.contains(text, ignoreCase = true)) return node
        for (i in 0 until node.childCount) {
            val hit = findByDesc(node.getChild(i), text)
            if (hit != null) return hit
        }
        return null
    }

    private fun nearestClickable(start: AccessibilityNodeInfo?): AccessibilityNodeInfo? {
        var n = start
        var hops = 0
        while (n != null && hops < 8) {
            if (n.isClickable) return n
            n = n.parent
            hops++
        }
        return null
    }

    private fun tapAt(x: Float, y: Float) {
        val path = Path().apply { moveTo(x, y) }
        val gesture = GestureDescription.Builder()
            .addStroke(GestureDescription.StrokeDescription(path, 0, 60))
            .build()
        dispatchGesture(gesture, null, null)
    }
}
