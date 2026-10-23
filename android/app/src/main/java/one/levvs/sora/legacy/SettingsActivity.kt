package one.levvs.sora.legacy

import android.app.Activity
import android.os.Bundle
import android.util.Log
import android.widget.EditText
import android.widget.Switch
import android.widget.TextView
import io.nekohasekai.libbox.Libbox
import org.json.JSONObject

/**
 * Settings that map to real fields — and nothing else:
 *  - local_port   -> "local_port" of the mobileapi plan document
 *  - TUN MTU      -> "mtu" of the sing-box tun inbound we inject
 *  - strict route -> "strict_route" of that same inbound
 * Plus a read-only engine view: Mobileapi.engineInfo() (the core's
 * static catalog: engines, pinned minimum versions, protocols,
 * features, default preference) and Libbox.version() (the actual
 * sing-box version inside libbox.aar). Changes apply on next connect.
 */
class SettingsActivity : Activity() {

    private lateinit var store: ServerStore
    private lateinit var portInput: EditText
    private lateinit var mtuInput: EditText
    private lateinit var strictSwitch: Switch

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        go.Seq.setContext(applicationContext)
        store = ServerStore(this)

        val column = scrollableContentColumn()
        column.label(getString(R.string.local_port_label), 14f)
        portInput = column.input("", number = true)
        portInput.setText(store.localPort().toString())

        column.label(getString(R.string.tun_mtu_label), 14f)
        mtuInput = column.input("", number = true)
        mtuInput.setText(store.tunMtu().toString())

        strictSwitch = Switch(this).apply {
            text = getString(R.string.strict_route_label)
            isChecked = store.strictRoute()
            setPadding(0, context.dp(8), 0, context.dp(8))
        }
        // Same row geometry as every builder-made row (full width),
        // not the default wrap_content the raw addView used to get.
        column.addView(strictSwitch, android.widget.LinearLayout.LayoutParams(
            android.view.ViewGroup.LayoutParams.MATCH_PARENT,
            android.view.ViewGroup.LayoutParams.WRAP_CONTENT))

        column.button(getString(R.string.save_button)) { save() }

        column.label(getString(R.string.engine_label), 20f)
        val engineView: TextView = column.label("", 14f)
        engineView.text = engineSummary()
    }

    private fun save() {
        val port = portInput.text.toString().toIntOrNull()
        if (port == null || port !in 1..65535) {
            toast(getString(R.string.local_port_invalid_toast))
            return
        }
        val mtu = mtuInput.text.toString().toIntOrNull()
        if (mtu == null || mtu !in 576..9000) {
            toast(getString(R.string.tun_mtu_invalid_toast))
            return
        }
        store.setLocalPort(port)
        store.setTunMtu(mtu)
        store.setStrictRoute(strictSwitch.isChecked)
        toast(getString(R.string.saved_toast))
    }

    private fun engineSummary(): String {
        val out = StringBuilder()
        try {
            out.append(getString(R.string.engine_libbox_line, Libbox.version())).append('\n')
        } catch (e: Exception) {
            Log.w(TAG, "libbox version unavailable", e)
            out.append(getString(R.string.engine_libbox_unavailable)).append('\n')
        }
        try {
            val info = JSONObject(mobileapi.Mobileapi.engineInfo())
            val engines = info.optJSONArray("engines")
            if (engines != null) {
                for (i in 0 until engines.length()) {
                    val engine = engines.getJSONObject(i)
                    out.append('\n')
                        .append(engine.optString("kind"))
                        .append(getString(R.string.engine_min_version, engine.optString("min_version"))).append('\n')
                        .append(getString(R.string.engine_protocols_line, joinArray(engine.optJSONArray("protocols")))).append('\n')
                        .append(getString(R.string.engine_features_line, joinArray(engine.optJSONArray("features")))).append('\n')
                }
            }
            val preference = info.optJSONArray("default_preference")
            if (preference != null) {
                out.append('\n')
                    .append(getString(R.string.engine_default_preference, joinArray(preference)))
            }
        } catch (e: Exception) {
            Log.w(TAG, "engine catalog unavailable", e)
            out.append('\n').append(getString(R.string.engine_catalog_unavailable))
        }
        return out.toString()
    }

    companion object {
        private const val TAG = "SettingsActivity"
    }

    private fun joinArray(array: org.json.JSONArray?): String {
        if (array == null) return ""
        val parts = ArrayList<String>(array.length())
        for (i in 0 until array.length()) parts += array.optString(i)
        return parts.joinToString(", ")
    }
}
