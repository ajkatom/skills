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

    /** Last human-readable status, surfaced in the app UI for tuning. */
    @Volatile var lastStatus: String = "idle"

    fun request(tiles: List<String>, windowMs: Long, act: GateAction) {
        targets = tiles.toMutableList()
        action = act
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

    fun store(dump: String) {
        lastDump = dump
        armed = false
    }
}
