package com.gatevoice.app

import android.Manifest
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.widget.Button
import android.widget.CompoundButton
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat

class MainActivity : AppCompatActivity() {

    private lateinit var prefs: Prefs

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        title = "GateVoice v${BuildConfig.VERSION_NAME}"
        prefs = Prefs(this)
        publishShortcuts()

        val edWake = findViewById<EditText>(R.id.edWake)
        val edGate = findViewById<EditText>(R.id.edGate)
        val edDoors = findViewById<EditText>(R.id.edDoors)
        val edPkg = findViewById<EditText>(R.id.edPkg)
        val edTapWin = findViewById<EditText>(R.id.edTapWin)
        val swWake = findViewById<CompoundButton>(R.id.swWake)

        // Load current settings.
        edWake.setText(prefs.wakeWord)
        edGate.setText(prefs.gateTile)
        edDoors.setText(prefs.doorsSpec)
        edPkg.setText(prefs.myqPackage)
        edTapWin.setText(prefs.tapWindowMs.toString())
        swWake.isChecked = prefs.wakeEnabled

        findViewById<Button>(R.id.btnMic).setOnClickListener {
            ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.RECORD_AUDIO), 1)
        }
        findViewById<Button>(R.id.btnNotif).setOnClickListener {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), 2)
            } else Toast.makeText(this, "Not needed on this Android", Toast.LENGTH_SHORT).show()
        }
        findViewById<Button>(R.id.btnAccess).setOnClickListener {
            startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
        }

        findViewById<Button>(R.id.btnSave).setOnClickListener {
            prefs.wakeWord = edWake.text.toString()
            prefs.gateTile = edGate.text.toString()
            prefs.doorsSpec = edDoors.text.toString()
            prefs.myqPackage = edPkg.text.toString()
            prefs.tapWindowMs = edTapWin.text.toString().toLongOrNull() ?: 12_000L
            Toast.makeText(this, "Saved", Toast.LENGTH_SHORT).show()
        }

        swWake.setOnCheckedChangeListener { _, checked ->
            if (checked && androidx.core.content.ContextCompat.checkSelfPermission(
                    this, Manifest.permission.RECORD_AUDIO
                ) != android.content.pm.PackageManager.PERMISSION_GRANTED
            ) {
                Toast.makeText(this, "Grant Microphone first", Toast.LENGTH_LONG).show()
                swWake.isChecked = false
                return@setOnCheckedChangeListener
            }
            prefs.wakeEnabled = checked
            if (checked) VoskWakeService.start(this) else VoskWakeService.stop(this)
        }

        findViewById<Button>(R.id.btnCapture).setOnClickListener {
            Diag.arm(20_000L)
            val launch = packageManager.getLaunchIntentForPackage(prefs.myqPackage)
            if (launch == null) {
                Toast.makeText(this, "myQ not found (${prefs.myqPackage})", Toast.LENGTH_LONG).show()
            } else {
                launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                startActivity(launch)
                Toast.makeText(
                    this, "Opening myQ — wait ~2s on its home screen, then return and tap 'View capture'",
                    Toast.LENGTH_LONG
                ).show()
            }
        }
        findViewById<Button>(R.id.btnViewDump).setOnClickListener {
            androidx.appcompat.app.AlertDialog.Builder(this)
                .setTitle("myQ screen capture")
                .setMessage(Diag.lastDump)
                .setPositiveButton("Copy") { _, _ ->
                    val cm = getSystemService(CLIPBOARD_SERVICE) as android.content.ClipboardManager
                    cm.setPrimaryClip(android.content.ClipData.newPlainText("capture", Diag.lastDump))
                    Toast.makeText(this, "Copied", Toast.LENGTH_SHORT).show()
                }
                .setNegativeButton("Close", null)
                .show()
        }

        findViewById<Button>(R.id.btnDryRun).setOnClickListener {
            val phrase = findViewById<EditText>(R.id.edTest).text.toString()
            val tiles = CommandParser.parseAll(phrase, prefs.gateTile, prefs.doorsMap())
            val action = CommandParser.detectAction(phrase).name.lowercase()
            findViewById<TextView>(R.id.tvParse).text =
                if (tiles.isEmpty()) "→ not understood (would ask again)"
                else "→ would $action: ${tiles.joinToString(", ")}"
        }
        findViewById<Button>(R.id.btnOpenGate).setOnClickListener { GateController.openTile(this, prefs.gateTile, selectedAction()) }
        findViewById<Button>(R.id.btnOpen1).setOnClickListener { openDoor(1) }
        findViewById<Button>(R.id.btnOpen2).setOnClickListener { openDoor(2) }
        findViewById<Button>(R.id.btnOpen3).setOnClickListener { openDoor(3) }
        findViewById<Button>(R.id.btnListen).setOnClickListener {
            startActivity(Intent(this, ListenActivity::class.java))
        }
        findViewById<Button>(R.id.btnRefresh).setOnClickListener { refreshStatus() }
    }

    /** Publish per-device app shortcuts so Google Assistant ("Hey Google, open
     *  the gate") and the launcher long-press menu can trigger GateVoice with
     *  no microphone of our own. */
    private fun publishShortcuts() {
        val devices = LinkedHashMap<String, String>()   // label -> myQ tile
        devices["Gate"] = prefs.gateTile
        prefs.doorsMap().forEach { (_, tile) -> devices[tile] = tile }

        val shortcuts = ArrayList<androidx.core.content.pm.ShortcutInfoCompat>()
        for ((_, tile) in devices) {
            for (act in listOf("open", "close")) {
                val label = "${act.replaceFirstChar { it.uppercase() }} $tile"
                val intent = Intent(this, ActionActivity::class.java).apply {
                    action = Intent.ACTION_VIEW
                    putExtra("device", tile)
                    putExtra("action", act)
                }
                shortcuts.add(
                    androidx.core.content.pm.ShortcutInfoCompat.Builder(
                        this, "$act-${tile.replace(" ", "_")}"
                    )
                        .setShortLabel(label)
                        .setLongLabel(label)
                        .setIcon(androidx.core.graphics.drawable.IconCompat.createWithResource(this, R.drawable.ic_launcher))
                        .setIntent(intent)
                        .build()
                )
            }
        }
        try {
            androidx.core.content.pm.ShortcutManagerCompat.setDynamicShortcuts(this, shortcuts)
        } catch (e: Exception) { /* best effort */ }
    }

    private fun selectedAction(): GateAction = when (
        findViewById<android.widget.RadioGroup>(R.id.rgAction).checkedRadioButtonId
    ) {
        R.id.rbClose -> GateAction.CLOSE
        R.id.rbToggle -> GateAction.TOGGLE
        else -> GateAction.OPEN
    }

    private fun openDoor(n: Int) {
        val tile = prefs.doorsMap()[n]
        if (tile == null) Toast.makeText(this, "Door $n not configured", Toast.LENGTH_SHORT).show()
        else GateController.openTile(this, tile, selectedAction())
    }

    private fun refreshStatus() {
        val acc = if (GateController.isAccessibilityEnabled(this)) "ON" else "OFF — enable it!"
        findViewById<TextView>(R.id.tvStatus).text =
            "Build v${BuildConfig.VERSION_NAME}\nAccessibility: $acc\n${PendingTap.lastStatus}"
    }

    override fun onResume() {
        super.onResume()
        refreshStatus()
    }
}
