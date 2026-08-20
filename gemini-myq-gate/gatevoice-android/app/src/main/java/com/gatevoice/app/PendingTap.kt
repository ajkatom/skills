package com.gatevoice.app

/**
 * Hand-off between "a command was understood" and "the accessibility service
 * taps the tile once myQ is on screen". The controller sets a target with an
 * expiry; the accessibility service consumes it when the myQ window appears.
 */
object PendingTap {
    @Volatile var targetTile: String? = null
    @Volatile var expiresAt: Long = 0L

    /** Last human-readable status, surfaced in the app UI for tuning. */
    @Volatile var lastStatus: String = "idle"

    fun request(tile: String, windowMs: Long) {
        targetTile = tile
        expiresAt = System.currentTimeMillis() + windowMs
        lastStatus = "waiting for myQ to show \"$tile\""
    }

    fun active(): Boolean =
        targetTile != null && System.currentTimeMillis() < expiresAt

    fun clear(status: String) {
        targetTile = null
        expiresAt = 0L
        lastStatus = status
    }
}
