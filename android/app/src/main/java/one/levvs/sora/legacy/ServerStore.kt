package one.levvs.sora.legacy

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/** One imported server, mirroring mobileapi's Server JSON shape. */
data class ServerEntry(
    val id: String,
    val name: String,
    val protocol: String,
    val server: String,
    val port: Long,
    /** The full server object exactly as mobileapi produced it.
     *  It carries the credential document: treat like a password —
     *  app-private storage only, never logged. */
    val raw: JSONObject,
) {
    fun label(): String {
        val title = name.ifBlank { id }
        return "$title — $protocol $server:$port"
    }
}

/**
 * Storage: imported servers as one JSON array file in app-private
 * storage (the exact array mobileapi returns, merged by id), the
 * selection and the tunables in SharedPreferences. No bundled or
 * hard-coded servers anywhere: an empty store is an empty list.
 */
class ServerStore(context: Context) {
    private val appContext = context.applicationContext
    private val prefs: SharedPreferences =
        appContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    private val serversFile: File get() = File(appContext.filesDir, SERVERS_FILE)

    // -- servers ----------------------------------------------------

    @Synchronized
    fun loadServers(): List<ServerEntry> {
        if (!serversFile.exists()) return emptyList()
        val text = serversFile.readText(Charsets.UTF_8)
        if (text.isBlank()) return emptyList()
        val array = JSONArray(text)
        val out = ArrayList<ServerEntry>(array.length())
        for (i in 0 until array.length()) {
            val obj = array.optJSONObject(i) ?: continue
            val id = obj.optString("id")
            if (id.isBlank()) continue
            out += ServerEntry(
                id = id,
                name = obj.optString("name"),
                protocol = obj.optString("protocol"),
                server = obj.optString("server"),
                port = obj.optLong("port"),
                raw = obj,
            )
        }
        return out
    }

    /** Merge a mobileapi import result (JSON array) into the store. */
    @Synchronized
    fun mergeImport(importJson: String): List<ServerEntry> {
        val incoming = JSONArray(importJson)
        val byId = LinkedHashMap<String, JSONObject>()
        for (entry in loadServers()) byId[entry.id] = entry.raw
        for (i in 0 until incoming.length()) {
            val obj = incoming.optJSONObject(i) ?: continue
            val id = obj.optString("id")
            if (id.isNotBlank()) byId[id] = obj
        }
        val merged = JSONArray()
        for (obj in byId.values) merged.put(obj)
        writeServers(merged)
        if (selectedId().isBlank() && byId.isNotEmpty()) {
            select(byId.keys.first())
        }
        return loadServers()
    }

    @Synchronized
    fun delete(id: String) {
        val kept = JSONArray()
        for (entry in loadServers()) if (entry.id != id) kept.put(entry.raw)
        writeServers(kept)
        if (selectedId() == id) select(loadServers().firstOrNull()?.id ?: "")
    }

    private fun writeServers(array: JSONArray) {
        val tmp = File(appContext.filesDir, "$SERVERS_FILE.tmp")
        tmp.writeText(array.toString(), Charsets.UTF_8)
        if (!tmp.renameTo(serversFile)) {
            serversFile.writeText(array.toString(), Charsets.UTF_8)
            tmp.delete()
        }
    }

    // -- selection & settings (SharedPreferences) -------------------

    fun selectedId(): String = prefs.getString(KEY_SELECTED, "") ?: ""
    fun select(id: String) { prefs.edit().putString(KEY_SELECTED, id).apply() }
    fun selected(): ServerEntry? = loadServers().firstOrNull { it.id == selectedId() }

    /** Local mixed-proxy port; a real field of the plan document. */
    fun localPort(): Int = prefs.getInt(KEY_LOCAL_PORT, 7890)
    fun setLocalPort(port: Int) { prefs.edit().putInt(KEY_LOCAL_PORT, port).apply() }

    /** TUN MTU; a real field of the sing-box tun inbound. */
    fun tunMtu(): Int = prefs.getInt(KEY_TUN_MTU, 1500)
    fun setTunMtu(mtu: Int) { prefs.edit().putInt(KEY_TUN_MTU, mtu).apply() }

    /** Strict route; a real field of the sing-box tun inbound. */
    fun strictRoute(): Boolean = prefs.getBoolean(KEY_STRICT_ROUTE, false)
    fun setStrictRoute(value: Boolean) { prefs.edit().putBoolean(KEY_STRICT_ROUTE, value).apply() }

    companion object {
        private const val PREFS = "sora-legacy"
        private const val SERVERS_FILE = "servers.json"
        private const val KEY_SELECTED = "selected_id"
        private const val KEY_LOCAL_PORT = "local_port"
        private const val KEY_TUN_MTU = "tun_mtu"
        private const val KEY_STRICT_ROUTE = "strict_route"
    }
}
