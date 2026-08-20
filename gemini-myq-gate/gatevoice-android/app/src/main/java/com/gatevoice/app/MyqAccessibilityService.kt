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
 * Presses the target tile inside the myQ app. When [PendingTap] is armed and a
 * myQ window appears, it searches the view tree for a node whose text or
 * content-description matches the tile, clicks the nearest clickable ancestor,
 * and (if that fails) taps the tile's on-screen location. Retries within the
 * arm window because myQ's device list can take a moment to render.
 */
class MyqAccessibilityService : AccessibilityService() {

    private val handler = Handler(Looper.getMainLooper())
    private var retryScheduled = false

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (!PendingTap.active()) return
        event ?: return
        val pkg = Prefs(this).myqPackage
        if (event.packageName?.toString() != pkg) return
        // A myQ window changed/updated — try to act.
        scheduleAttempts()
    }

    override fun onInterrupt() {}

    private fun scheduleAttempts() {
        if (retryScheduled) return
        retryScheduled = true
        var attempts = 0
        val tick = object : Runnable {
            override fun run() {
                if (!PendingTap.active()) { retryScheduled = false; return }
                val target = PendingTap.targetTile
                if (target != null && tryTap(target)) {
                    PendingTap.clear("tapped \"$target\"")
                    retryScheduled = false
                    return
                }
                attempts++
                if (System.currentTimeMillis() < PendingTap.expiresAt && attempts < 40) {
                    handler.postDelayed(this, 300)
                } else {
                    PendingTap.clear("gave up finding \"$target\" (not on screen?)")
                    retryScheduled = false
                }
            }
        }
        handler.post(tick)
    }

    private fun tryTap(tileText: String): Boolean {
        val root = rootInActiveWindow ?: return false
        val node = findByText(root, tileText) ?: findByDesc(root, tileText) ?: return false
        // Prefer clicking a clickable ancestor (the tile card / its open button).
        val clickable = nearestClickable(node)
        if (clickable != null && clickable.performAction(AccessibilityNodeInfo.ACTION_CLICK)) {
            PendingTap.lastStatus = "clicked node for \"$tileText\""
            maybeConfirm(root)
            return true
        }
        // Fallback: dispatch a tap gesture at the node's center.
        val rect = Rect()
        node.getBoundsInScreen(rect)
        if (rect.width() > 0 && rect.height() > 0) {
            tapAt(rect.exactCenterX(), rect.exactCenterY())
            PendingTap.lastStatus = "gesture-tapped \"$tileText\""
            maybeConfirm(root)
            return true
        }
        return false
    }

    /** If myQ shows a confirmation ("Open"/"Confirm"/"Yes"), press it too. */
    private fun maybeConfirm(root: AccessibilityNodeInfo?) {
        root ?: return
        handler.postDelayed({
            val r = rootInActiveWindow ?: return@postDelayed
            for (label in listOf("Open", "Confirm", "Yes", "OK")) {
                val n = findByText(r, label) ?: continue
                nearestClickable(n)?.performAction(AccessibilityNodeInfo.ACTION_CLICK)
                break
            }
        }, 700)
    }

    private fun findByText(root: AccessibilityNodeInfo, text: String): AccessibilityNodeInfo? {
        val matches = root.findAccessibilityNodeInfosByText(text)
        // Prefer an exact (case-insensitive) match if present.
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
