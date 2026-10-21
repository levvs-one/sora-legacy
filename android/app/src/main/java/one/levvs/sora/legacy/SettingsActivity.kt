package one.levvs.sora.legacy

import android.app.Activity
import android.os.Bundle
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

        val column = contentColumn()
        column.label("Local proxy port (plan local_port, 1–65535)", 14f)
        portInput = column.input("", number = true)
        portInput.setText(store.localPort().toString())

        column.label("TUN MTU (tun inbound mtu, 576–9000)", 14f)
        mtuInput = column.input("", number = true)
        mtuInput.setText(store.tunMtu().toString())

        strictSwitch = Switch(this).apply {
            text = "Strict route (tun inbound strict_route)"
            isChecked = store.strictRoute()
        }
        column.addView(strictSwitch)

        column.button("Save (applies on next connect)") { save() }

        column.label("Engine", 18f)
        val engineView: TextView = column.label("", 13f)
        engineView.text = engineSummary()
    }

    private fun save() {
        val port = portInput.text.toString().toIntOrNull()
        if (port == null || port !in 1..65535) {
            toast("Local port must be a number in 1–65535.")
            return
        }
        val mtu = mtuInput.text.toString().toIntOrNull()
        if (mtu == null || mtu !in 576..9000) {
            toast("MTU must be a number in 576–9000.")
            return
        }
        store.setLocalPort(port)
        store.setTunMtu(mtu)
        store.setStrictRoute(strictSwitch.isChecked)
        toast("Saved.")
    }

    private fun engineSummary(): String {
        val out = StringBuilder()
        try {
            out.append("sing-box (libbox): ").append(Libbox.version()).append('\n')
        } catch (e: Exception) {
            out.append("sing-box (libbox): unavailable (${e.javaClass.simpleName})\n")
        }
        try {
            val info = JSONObject(mobileapi.Mobileapi.engineInfo())
            val engines = info.optJSONArray("engines")
            if (engines != null) {
                for (i in 0 until engines.length()) {
                    val engine = engines.getJSONObject(i)
                    out.append('\n')
                        .append(engine.optString("kind"))
                        .append(" ≥ ").append(engine.optString("min_version")).append('\n')
                        .append("  protocols: ").append(joinArray(engine.optJSONArray("protocols"))).append('\n')
                        .append("  features: ").append(joinArray(engine.optJSONArray("features"))).append('\n')
                }
            }
            val preference = info.optJSONArray("default_preference")
            if (preference != null) {
                out.append("\ndefault preference: ").append(joinArray(preference))
            }
        } catch (e: Exception) {
            out.append("\ncore catalog unavailable: ").append(e.message ?: e.javaClass.simpleName)
        }
        return out.toString()
    }

    private fun joinArray(array: org.json.JSONArray?): String {
        if (array == null) return ""
        val parts = ArrayList<String>(array.length())
        for (i in 0 until array.length()) parts += array.optString(i)
        return parts.joinToString(", ")
    }
}
