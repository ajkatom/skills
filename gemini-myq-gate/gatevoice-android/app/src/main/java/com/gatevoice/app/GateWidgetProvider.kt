package com.gatevoice.app

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.Context
import android.content.Intent
import android.widget.RemoteViews

/** Home-screen widget: one tap opens the listen screen. */
class GateWidgetProvider : AppWidgetProvider() {
    override fun onUpdate(context: Context, mgr: AppWidgetManager, ids: IntArray) {
        for (id in ids) {
            val views = RemoteViews(context.packageName, R.layout.gate_widget)
            val intent = Intent(context, ListenActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            val pi = PendingIntent.getActivity(context, 0, intent, flags)
            views.setOnClickPendingIntent(R.id.widget_button, pi)
            mgr.updateAppWidget(id, views)
        }
    }
}
