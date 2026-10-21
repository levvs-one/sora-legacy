package one.levvs.sora.legacy

import org.json.JSONArray
import org.json.JSONObject

/**
 * mobileapi renders an application-mode plan: a loopback mixed
 * inbound, no TUN (its doc comment is explicit — "Mobile clients own
 * the TUN"). On Android the TUN is created by sing-box's tun inbound
 * asking our PlatformInterface.openTun() for a fd, so the client adds
 * exactly that inbound to the rendered document before handing it to
 * Libbox.newService. If a future render ever ships its own tun
 * inbound, it is left untouched.
 *
 * The addresses mirror the desktop render's session shape
 * (172.19.0.1/30 gives libbox the second address its
 * GetDNSServerAddress() derives the hijack DNS server from; a /32
 * would make it throw).
 */
object TunConfig {
    const val TUN_TAG = "tun-in"
    const val INET4_ADDRESS = "172.19.0.1/30"
    const val INET6_ADDRESS = "fdfe:dcba:9876::1/126"

    fun injectTunInbound(configJson: String, mtu: Int, strictRoute: Boolean): String {
        val root = JSONObject(configJson)
        val inbounds = root.optJSONArray("inbounds") ?: JSONArray().also { root.put("inbounds", it) }
        for (i in 0 until inbounds.length()) {
            if (inbounds.optJSONObject(i)?.optString("type") == "tun") return configJson
        }
        val tun = JSONObject()
            .put("type", "tun")
            .put("tag", TUN_TAG)
            .put("address", JSONArray().put(INET4_ADDRESS).put(INET6_ADDRESS))
            .put("mtu", mtu)
            .put("auto_route", true)
            .put("strict_route", strictRoute)
            .put("stack", "mixed")
        inbounds.put(tun)
        return root.toString()
    }
}
