package com.gatevoice.app

/**
 * Hand-off between "a command was understood" and "the accessibility service
 * taps the tile(s) once myQ is on screen". Holds a QUEUE so one command can
 * open several devices ("door 2 and gate"): the service taps the head of the
 * queue, then advances to the next.
 */
object PendingTap {
    @Volatile var targets: MutableList<String> = mutableListOf()
    @Volatile var expiresAt: Long = 0L
    @Volatile var action: GateAction = GateAction.OPEN

    /** High-water marks so status reflects the BEST state reached, not just the
     *  last poll (which is usually GateVoice, since you switch back to read it). */
    @Volatile var sawMyQ: Boolean = false
    @Volatile var sawNode: Boolean = false

    /** Tiles already tapped for THIS request — guarantees one tap per door
     *  (prevents the open-then-close double toggle) while still allowing a
     *  multi-device command to tap each different door once. */
    @Volatile var tapped: MutableSet<String> = HashSet()

    /** Last human-readable status, surfaced in the app UI for tuning. */
    @Volatile var lastStatus: String = "idle"

    fun request(tiles: List<String>, windowMs: Long, act: GateAction) {
        targets = tiles.toMutableList()
        action = act
        sawMyQ = false
        sawNode = false
        tapped = HashSet()
        expiresAt = System.currentTimeMillis() + windowMs
        lastStatus = "waiting for myQ to ${act.name.lowercase()} ${tiles.joinToString(", ")}"
    }

    fun current(): String? = targets.firstOrNull()

    fun completeCurrent() {
        if (targets.isNotEmpty()) targets.removeAt(0)
    }

    fun active(): Boolean =
        targets.isNotEmpty() && System.currentTimeMillis() < expiresAt

    fun clear(status: String) {
        targets = mutableListOf()
        expiresAt = 0L
        lastStatus = status
    }
}

/**
 * Diagnostic capture: when armed, the accessibility service dumps the myQ
 * window's node tree so we can see the real, accessible labels (or discover
 * that myQ blocks accessibility). Purely for troubleshooting the tap.
 */
object Diag {
    @Volatile var armed: Boolean = false
    @Volatile var expiresAt: Long = 0L
    @Volatile var lastDump: String = "(no capture yet — tap \"Capture myQ screen\", switch to myQ, wait 2s, come back and View)"

    fun arm(windowMs: Long) {
        armed = true
        expiresAt = System.currentTimeMillis() + windowMs
    }

    fun active(): Boolean = armed && System.currentTimeMillis() < expiresAt

    /** Continuous within the armed window: keeps the LATEST myQ screen shown,
     *  so you can arm it, navigate to the detail screen you want, and that's
     *  what gets saved. Stops when the window expires. */
    fun store(dump: String) {
        lastDump = dump
    }
}
