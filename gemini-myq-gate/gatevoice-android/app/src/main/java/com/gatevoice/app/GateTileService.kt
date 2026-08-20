package com.gatevoice.app

import android.content.Intent
import android.service.quicksettings.TileService

/** Quick Settings tile: one tap opens the listen screen. */
class GateTileService : TileService() {
    override fun onClick() {
        super.onClick()
        val i = Intent(this, ListenActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        // Collapse the shade and launch the (translucent) listen activity.
        startActivityAndCollapse(i)
    }
}
