package one.levvs.sora.legacy

import io.nekohasekai.libbox.NetworkInterface
import io.nekohasekai.libbox.NetworkInterfaceIterator
import io.nekohasekai.libbox.RoutePrefix
import io.nekohasekai.libbox.RoutePrefixIterator
import io.nekohasekai.libbox.StringIterator
import io.nekohasekai.libbox.TunOptions

/** StringIterator over a snapshot list (libbox iterator.go contract:
 *  destructive Next(), HasNext(), Len()). */
class ListStringIterator(items: List<String>) : StringIterator {
    private val items = items.toList()
    private var index = 0
    override fun hasNext(): Boolean = index < items.size
    override fun len(): Int = items.size - index
    override fun next(): String = if (hasNext()) items[index++] else ""
}

class ListNetworkInterfaceIterator(items: List<NetworkInterface>) : NetworkInterfaceIterator {
    private val items = items.toList()
    private var index = 0
    override fun hasNext(): Boolean = index < items.size
    override fun next(): NetworkInterface? = if (hasNext()) items[index++] else null
}

/** Drain helpers for the Go-side iterator interfaces. */
fun StringIterator?.drainStrings(): List<String> {
    if (this == null) return emptyList()
    val out = ArrayList<String>()
    while (hasNext()) out += next()
    return out
}

fun RoutePrefixIterator?.drainPrefixes(): List<RoutePrefix> {
    if (this == null) return emptyList()
    val out = ArrayList<RoutePrefix>()
    while (hasNext()) next()?.let { out += it }
    return out
}

/** TunOptions split by address family, parsed once for the Builder. */
class TunPlan(options: TunOptions) {
    val mtu: Int = options.getMTU()
    val autoRoute: Boolean = options.getAutoRoute()
    val strictRoute: Boolean = options.getStrictRoute()
    val inet4Address: List<RoutePrefix> = options.getInet4Address().drainPrefixes()
    val inet6Address: List<RoutePrefix> = options.getInet6Address().drainPrefixes()
    val inet4Routes: List<RoutePrefix> = options.getInet4RouteAddress().drainPrefixes()
    val inet6Routes: List<RoutePrefix> = options.getInet6RouteAddress().drainPrefixes()
    val inet4Exclude: List<RoutePrefix> = options.getInet4RouteExcludeAddress().drainPrefixes()
    val inet6Exclude: List<RoutePrefix> = options.getInet6RouteExcludeAddress().drainPrefixes()
    val includePackage: List<String> = options.getIncludePackage().drainStrings()
    val excludePackage: List<String> = options.getExcludePackage().drainStrings()
    val httpProxyEnabled: Boolean = options.isHTTPProxyEnabled()
    val httpProxyServer: String = options.getHTTPProxyServer() ?: ""
    val httpProxyPort: Int = options.getHTTPProxyServerPort()
    val httpProxyBypass: List<String> = options.getHTTPProxyBypassDomain().drainStrings()
    /** Go derives the hijack DNS address from the first IPv4 TUN
     *  address; it throws when that is impossible, so callers treat a
     *  failure as "no DNS server to hand to the Builder". */
    val dnsServer: String? = try {
        options.getDNSServerAddress()?.getValue()?.takeIf { it.isNotBlank() }
    } catch (e: Exception) {
        null
    }
}
