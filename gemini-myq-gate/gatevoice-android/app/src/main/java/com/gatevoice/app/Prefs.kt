package com.gatevoice.app

import android.content.Context

/** Simple persisted settings: wake word, myQ package, tile names, tap tuning. */
class Prefs(context: Context) {
    private val sp = context.getSharedPreferences("gatevoice", Context.MODE_PRIVATE)

    var wakeWord: String
        get() = sp.getString("wake", "sesame") ?: "sesame"
        set(v) = sp.edit().putString("wake", v.lowercase().trim()).apply()

    var myqPackage: String
        get() = sp.getString("pkg", DEFAULT_MYQ_PKG) ?: DEFAULT_MYQ_PKG
        set(v) = sp.edit().putString("pkg", v.trim()).apply()

    var gateTile: String
        get() = sp.getString("gate", CommandParser.DEFAULT_GATE) ?: CommandParser.DEFAULT_GATE
        set(v) = sp.edit().putString("gate", v).apply()

    /** Stored as "1=Garage Door 1;2=Garage Door 2;3=Garage Door 3". */
    var doorsSpec: String
        get() = sp.getString("doors", defaultDoorsSpec()) ?: defaultDoorsSpec()
        set(v) = sp.edit().putString("doors", v).apply()

    /** Milliseconds the accessibility service keeps trying to find the tile. */
    var tapWindowMs: Long
        get() = sp.getLong("tapwin", 12_000L)
        set(v) = sp.edit().putLong("tapwin", v).apply()

    var wakeEnabled: Boolean
        get() = sp.getBoolean("wakeon", false)
        set(v) = sp.edit().putBoolean("wakeon", v).apply()

    fun doorsMap(): Map<Int, String> {
        val out = linkedMapOf<Int, String>()
        for (part in doorsSpec.split(";")) {
            val kv = part.split("=", limit = 2)
            if (kv.size == 2) kv[0].trim().toIntOrNull()?.let { out[it] = kv[1].trim() }
        }
        return if (out.isEmpty()) CommandParser.defaultDoors else out
    }

    companion object {
        const val DEFAULT_MYQ_PKG = "com.chamberlain.android.liftmaster.myq"
        fun defaultDoorsSpec() =
            CommandParser.defaultDoors.entries.joinToString(";") { "${it.key}=${it.value}" }
    }
}
