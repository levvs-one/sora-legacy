package one.levvs.sora.legacy

import io.nekohasekai.libbox.ExchangeContext
import io.nekohasekai.libbox.LocalDNSTransport
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

/**
 * Platform "local" DNS transport for libbox (dns.go contract).
 *
 * Raw() is false, so libbox only ever calls Lookup(): it hands us a
 * domain and a network ("ip4"/"ip6") and expects the resolved
 * addresses back through ExchangeContext.success() as newline-joined
 * IPs. We answer with the system resolver (InetAddress, i.e. the
 * platform netd path) — the same source Android apps themselves use.
 * Exchange() (raw DNS packets) is therefore unreachable by contract;
 * it throws instead of silently misbehaving, and if a future libbox
 * ever called it with Raw()==false that throw surfaces as a DNS
 * error in the engine log, not a wrong answer.
 */
class LocalDnsTransport : LocalDNSTransport {
    override fun raw(): Boolean = false

    override fun lookup(context: ExchangeContext, network: String, domain: String) {
        val host = domain.trim().removeSuffix(".")
        val resolved = InetAddress.getAllByName(host)
        val filtered = resolved.filter { address ->
            when (network) {
                "ip4" -> address is Inet4Address
                "ip6" -> address is Inet6Address
                else -> true
            }
        }
        // Resolved addresses go straight to the Go side, which parses
        // them as plain IPs: strip any IPv6 zone (a link-local result
        // can arrive scoped) — see zoneFreeHostAddress in
        // LibboxHelpers.kt.
        context.success(filtered.joinToString("\n") { it.zoneFreeHostAddress() ?: "" })
    }

    override fun exchange(context: ExchangeContext, message: ByteArray) {
        throw UnsupportedOperationException(
            "local DNS transport is lookup-only (raw() == false)"
        )
    }
}
