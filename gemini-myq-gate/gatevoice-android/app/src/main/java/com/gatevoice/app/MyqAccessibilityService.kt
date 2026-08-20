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

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        event ?: return
        val pkg = Prefs(this).myqPackage
        if (event.packageName?.toString() != pkg) return

        // Diagnostic capture takes priority.
        if (Diag.active()) captureNow()

        if (PendingTap.active()) scheduleAttempts()
    }

    override fun onInterrupt() {}

    private fun scheduleAttempts() {
        if (retryScheduled) return
        retryScheduled = true
        var attempts = 0
        val tick = object : Runnable {
            override fun run() {
                if (!PendingTap.active()) { retryScheduled = false; return }
                val target = PendingTap.current()
                if (target != null && tryTap(target)) {
                    PendingTap.completeCurrent()
                    val next = PendingTap.current()
                    if (next == null) {
                        PendingTap.clear("done")
                        retryScheduled = false
                        return
                    }
                    // More devices to open: pause, then continue on the list.
                    PendingTap.lastStatus = "opened $target, now $next"
                    attempts = 0
                    handler.postDelayed(this, 1600)
                    return
                }
                attempts++
                if (System.currentTimeMillis() < PendingTap.expiresAt && attempts < 40) {
                    handler.postDelayed(this, 300)
                } else {
                    PendingTap.clear(failureStatus(target))
                    retryScheduled = false
                }
            }
        }
        handler.post(tick)
    }

    private fun tryTap(tileText: String): Boolean {
        val root = rootInActiveWindow ?: return false
        val node = findByText(root, tileText) ?: findByDesc(root, tileText) ?: return false
        val clickable = nearestClickable(node)
        if (clickable != null && clickable.performAction(AccessibilityNodeInfo.ACTION_CLICK)) {
            PendingTap.lastStatus = "clicked node for \"$tileText\""
            maybeConfirm()
            return true
        }
        val rect = Rect()
        node.getBoundsInScreen(rect)
        if (rect.width() > 0 && rect.height() > 0) {
            tapAt(rect.exactCenterX(), rect.exactCenterY())
            PendingTap.lastStatus = "gesture-tapped \"$tileText\""
            maybeConfirm()
            return true
        }
        return false
    }

    /** If myQ shows a confirmation ("Open"/"Confirm"/"Yes"), press it too. */
    private fun maybeConfirm() {
        handler.postDelayed({
            val r = rootInActiveWindow ?: return@postDelayed
            for (label in listOf("Open", "Confirm", "Yes", "OK")) {
                val n = findByText(r, label) ?: continue
                nearestClickable(n)?.performAction(AccessibilityNodeInfo.ACTION_CLICK)
                break
            }
        }, 700)
    }

    /** Build a status that reveals what myQ actually exposed, so we can tune. */
    private fun failureStatus(target: String?): String {
        val root = rootInActiveWindow
            ?: return "no match for \"$target\": myQ exposed NO content to accessibility " +
                "(is the service enabled? did myQ block accessibility?)"
        val labels = collectLabels(root, mutableListOf(), 0).distinct().take(25)
        return if (labels.isEmpty()) {
            "no match for \"$target\": myQ window had 0 readable labels (likely blocked)"
        } else {
            "no match for \"$target\". Saw: " + labels.joinToString(" | ")
        }
    }

    private fun captureNow() {
        val root = rootInActiveWindow
        if (root == null) {
            Diag.store("CAPTURE: rootInActiveWindow was null — myQ likely blocks accessibility, " +
                "or the service isn't reading this window.")
            return
        }
        val sb = StringBuilder("CAPTURE of ${Prefs(this).myqPackage}\n")
        dumpTree(root, sb, 0)
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

    private fun findByText(root: AccessibilityNodeInfo, text: String): AccessibilityNodeInfo? {
        val matches = root.findAccessibilityNodeInfosByText(text)
        return matches.firstOrNull { it.text?.toString().equals(text, ignoreCase = true) }
            ?: matches.firstOrNull()
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
