package one.levvs.sora.legacy

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.TextView

/** Status screen: connection state, selected server, connect /
 *  disconnect, and entry points to Servers and Settings. */
class MainActivity : Activity() {

    private lateinit var store: ServerStore
    private lateinit var statusView: TextView
    private lateinit var serverView: TextView
    private lateinit var toggleButton: Button
    private lateinit var logView: TextView

    private val stateListener: () -> Unit = { runOnUiThread { refresh() } }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        go.Seq.setContext(applicationContext)
        store = ServerStore(this)

        val column = contentColumn()
        column.label(getString(R.string.app_name), 22f)
        statusView = column.label("—")
        serverView = column.label("—")
        toggleButton = column.button("Connect") { onToggle() }
        column.button("Servers") { startActivity(Intent(this, ServersActivity::class.java)) }
        column.button("Settings") { startActivity(Intent(this, SettingsActivity::class.java)) }
        logView = column.label("", 12f)

        requestNotificationPermission()
    }

    override fun onResume() {
        super.onResume()
        VpnState.addListener(stateListener)
        refresh()
    }

    override fun onPause() {
        VpnState.removeListener(stateListener)
        super.onPause()
    }

    private fun refresh() {
        val selected = store.selected()
        serverView.text = if (selected == null) {
            "No server selected — open Servers to import one."
        } else {
            "Server: ${selected.label()}"
        }
        val state = VpnState.state
        statusView.text = when (state) {
            ConnState.STOPPED -> "Status: disconnected"
            ConnState.STARTING -> "Status: connecting…"
            ConnState.RUNNING -> "Status: connected"
            ConnState.STOPPING -> "Status: disconnecting…"
            ConnState.ERROR -> "Status: failed — ${VpnState.lastError}"
        }
        toggleButton.text = when (state) {
            ConnState.RUNNING, ConnState.STARTING -> "Disconnect"
            else -> "Connect"
        }
        toggleButton.isEnabled = state != ConnState.STOPPING
        val log = VpnState.recentLog().takeLast(8)
        logView.text = if (log.isEmpty()) "" else "Engine log (last lines):\n" + log.joinToString("\n")
    }

    private fun onToggle() {
        when (VpnState.state) {
            ConnState.RUNNING, ConnState.STARTING -> {
                startService(Intent(this, SoraVpnService::class.java).setAction(SoraVpnService.ACTION_STOP))
            }
            else -> {
                if (store.selected() == null) {
                    toast("No server selected — import one in Servers first.")
                    return
                }
                // The system VPN consent dialog: prepare() returns an
                // intent when consent is still needed, null when the
                // app is already the active/prepared VPN.
                val consent = VpnService.prepare(this)
                if (consent != null) {
                    @Suppress("DEPRECATION") startActivityForResult(consent, REQUEST_VPN)
                } else {
                    startVpn()
                }
            }
        }
    }

    @Deprecated("Activity result API predates AndroidX; framework replacement is unavailable by design")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN) {
            if (resultCode == RESULT_OK) startVpn()
            else toast("VPN permission was not granted; cannot connect.")
        }
    }

    private fun startVpn() {
        val intent = Intent(this, SoraVpnService::class.java).setAction(SoraVpnService.ACTION_START)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) startForegroundService(intent) else startService(intent)
    }

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQUEST_NOTIFICATIONS)
        }
    }

    companion object {
        private const val REQUEST_VPN = 100
        private const val REQUEST_NOTIFICATIONS = 101
    }
}
