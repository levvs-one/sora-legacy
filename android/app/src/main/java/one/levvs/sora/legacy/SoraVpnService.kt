package one.levvs.sora.legacy

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.IpPrefix
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.ProxyInfo
import android.net.VpnService
import android.net.wifi.WifiManager
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Base64
import android.util.Log
import io.nekohasekai.libbox.BoxService
import io.nekohasekai.libbox.InterfaceUpdateListener
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.LocalDNSTransport
import io.nekohasekai.libbox.NetworkInterfaceIterator
import io.nekohasekai.libbox.PlatformInterface
import io.nekohasekai.libbox.SetupOptions
import io.nekohasekai.libbox.StringIterator
import io.nekohasekai.libbox.TunOptions
import mobileapi.Mobileapi
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.concurrent.Executors
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import io.nekohasekai.libbox.NetworkInterface as LibboxInterface
import io.nekohasekai.libbox.Notification as LibboxNotification

/**
 * The VPN service: owns the TUN through Android's VpnService and the
 * sing-box engine through libbox, implementing libbox's
 * PlatformInterface (sing-box 1.12.12, experimental/libbox/platform.go)
 * against real platform APIs.
 *
 * Connect flow (on a worker thread — gomobile calls block):
 *   selected server (ServerStore) -> plan document with the stored
 *   local port -> Mobileapi.buildPlan -> Mobileapi.renderSingBoxConfig
 *   -> TunConfig.injectTunInbound -> filesDir/config.json ->
 *   Libbox.setup (once per process) -> Libbox.newService(config, this)
 *   -> BoxService.start(). The engine then calls back into openTun()
 *   below to obtain the TUN fd.
 */
class SoraVpnService : VpnService(), PlatformInterface {

    private val executor = Executors.newSingleThreadExecutor()
    private var boxService: BoxService? = null
    private var tunFd: ParcelFileDescriptor? = null
    private var setupDone = false

    private val connectivity: ConnectivityManager
        get() = getSystemService(ConnectivityManager::class.java)
    private val notifications: NotificationManager
        get() = getSystemService(NotificationManager::class.java)

    // Default-interface monitor state.
    private var monitorListener: InterfaceUpdateListener? = null
    private var monitorCallback: ConnectivityManager.NetworkCallback? = null

    override fun onCreate() {
        super.onCreate()
        go.Seq.setContext(applicationContext)
        createChannels()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> executor.execute { stopEngine(userInitiated = true) }
            ACTION_START, null -> executor.execute { startEngine() }
        }
        return START_STICKY
    }

    override fun onRevoke() {
        executor.execute { stopEngine(userInitiated = false) }
        super.onRevoke()
    }

    override fun onDestroy() {
        // Best effort on process teardown; the normal path is ACTION_STOP.
        try { boxService?.close() } catch (e: Exception) { Log.w(TAG, "close on destroy", e) }
        boxService = null
        executor.shutdown()
        super.onDestroy()
    }

    // -- engine lifecycle --------------------------------------------

    private fun startEngine() {
        if (boxService != null) return
        val store = ServerStore(this)
        val selected = store.selected()
        if (selected == null) {
            failStart("No server selected. Import a link or a subscription first.")
            return
        }
        VpnState.transition(ConnState.STARTING, server = selected.label())
        startForegroundCompat(buildStatusNotification("Connecting to ${selected.label()}…"))
        try {
            // Plan document: the one selected server plus the stored
            // local port — both real fields of mobileapi's Plan shape.
            val planInput = JSONObject()
                .put("local_port", store.localPort())
                .put("servers", JSONArray().put(selected.raw))
                .toString()
            val plan = Mobileapi.buildPlan(planInput)
            val rendered = Mobileapi.renderSingBoxConfig(plan)
            val config = TunConfig.injectTunInbound(rendered, store.tunMtu(), store.strictRoute())

            val configFile = File(filesDir, CONFIG_FILE)
            configFile.writeText(config, Charsets.UTF_8)

            if (!setupDone) {
                val options = SetupOptions()
                options.setBasePath(filesDir.absolutePath)
                options.setWorkingPath(File(filesDir, "libbox").absolutePath)
                options.setTempPath(cacheDir.absolutePath)
                options.setIsTVOS(false)
                // The libbox escape hatch for the Android stack-size
                // issue in the Go runtime (setup.go): on Android it
                // makes BoxService.start/close hop threads as the
                // contract intends.
                options.setFixAndroidStack(true)
                Libbox.setup(options)
                setupDone = true
            }
            val service = Libbox.newService(config, this)
            service.start()
            boxService = service
            VpnState.transition(ConnState.RUNNING, server = selected.label())
            notifications.notify(NOTIFICATION_ID, buildStatusNotification("Connected — ${selected.label()}"))
        } catch (e: Exception) {
            Log.e(TAG, "start failed", e)
            failStart(userMessage(e))
        }
    }

    private fun stopEngine(userInitiated: Boolean) {
        if (boxService == null && VpnState.state == ConnState.STOPPED) return
        VpnState.transition(ConnState.STOPPING)
        try {
            boxService?.close()
        } catch (e: Exception) {
            Log.w(TAG, "engine close failed", e)
        }
        boxService = null
        try { tunFd?.close() } catch (e: Exception) { Log.w(TAG, "tun close failed", e) }
        tunFd = null
        VpnState.transition(ConnState.STOPPED, server = "")
        stopForegroundCompat()
        stopSelf()
    }

    private fun failStart(message: String) {
        VpnState.transition(ConnState.ERROR, error = message)
        stopForegroundCompat()
        stopSelf()
    }

    /** Honest user-facing text: the engine's own message, never a stack trace. */
    private fun userMessage(e: Exception): String =
        e.message?.takeIf { it.isNotBlank() } ?: "The engine refused to start (${e.javaClass.simpleName})."

    // -- foreground notification ---------------------------------------

    private fun createChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            notifications.createNotificationChannel(
                NotificationChannel(CHANNEL_VPN, getString(R.string.channel_vpn), NotificationManager.IMPORTANCE_LOW)
            )
            notifications.createNotificationChannel(
                NotificationChannel(CHANNEL_ALERTS, getString(R.string.channel_alerts), NotificationManager.IMPORTANCE_DEFAULT)
            )
        }
    }

    private fun buildStatusNotification(text: String): Notification {
        val openApp = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_VPN)
        } else {
            @Suppress("DEPRECATION") Notification.Builder(this)
        }
        return builder
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_vp_phone_call)
            .setContentIntent(openApp)
            .setOngoing(true)
            .build()
    }

    private fun startForegroundCompat(notification: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun stopForegroundCompat() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION") stopForeground(true)
        }
    }

    // -- PlatformInterface: TUN ----------------------------------------

    /**
     * libbox asks for the TUN here (platform.go OpenTun). Everything
     * the Builder gets comes from the TunOptions the engine computed
     * from the config's tun inbound — addresses, route address sets,
     * route exclusions, DNS hijack address, per-package filters and
     * the platform HTTP proxy — nothing is invented locally.
     */
    override fun openTun(options: TunOptions): Int {
        val plan = TunPlan(options)
        val builder = Builder()
            .setSession(getString(R.string.app_name))
            .setMtu(if (plan.mtu > 0) plan.mtu else 1500)

        for (prefix in plan.inet4Address) builder.addAddress(prefix.address(), prefix.prefix())
        for (prefix in plan.inet6Address) builder.addAddress(prefix.address(), prefix.prefix())

        if (plan.autoRoute) {
            if (plan.inet4Routes.isEmpty()) builder.addRoute("0.0.0.0", 0)
            else for (route in plan.inet4Routes) builder.addRoute(route.address(), route.prefix())
            if (plan.inet6Routes.isEmpty()) {
                if (plan.inet6Address.isNotEmpty()) builder.addRoute("::", 0)
            } else for (route in plan.inet6Routes) builder.addRoute(route.address(), route.prefix())
        }
        // Excluded routes need the IpPrefix API (33+); on older
        // systems the exclusion set is dropped and auto-route covers
        // everything — a documented platform limit, not a silent one:
        // it is named in the README's verify-on-device list.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            for (route in plan.inet4Exclude + plan.inet6Exclude) {
                builder.excludeRoute(IpPrefix(InetAddress.getByName(route.address()), route.prefix()))
            }
        }

        plan.dnsServer?.let { builder.addDnsServer(it) }

        for (pkg in plan.includePackage) {
            try { builder.addAllowedApplication(pkg) }
            catch (e: PackageManager.NameNotFoundException) { Log.w(TAG, "include package not installed: $pkg") }
        }
        for (pkg in plan.excludePackage) {
            try { builder.addDisallowedApplication(pkg) }
            catch (e: PackageManager.NameNotFoundException) { Log.w(TAG, "exclude package not installed: $pkg") }
        }

        if (plan.httpProxyEnabled && Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setHttpProxy(
                ProxyInfo.buildDirectProxy(plan.httpProxyServer, plan.httpProxyPort, plan.httpProxyBypass)
            )
        }

        val pfd = builder.establish()
            ?: throw IllegalStateException("VpnService.Builder.establish() returned null (VPN permission revoked?)")
        tunFd = pfd
        return pfd.detachFd()
    }

    // -- PlatformInterface: interface control --------------------------

    override fun usePlatformAutoDetectInterfaceControl(): Boolean = true

    /** The engine's outgoing sockets must bypass the TUN it owns:
     *  that is exactly VpnService.protect(). */
    override fun autoDetectInterfaceControl(fd: Int) {
        if (!protect(fd)) throw IllegalStateException("VpnService.protect($fd) failed")
    }

    // -- PlatformInterface: DNS -----------------------------------------

    override fun localDNSTransport(): LocalDNSTransport = LocalDnsTransport()

    override fun clearDNSCache() {
        // Android exposes no per-app system DNS cache flush. The
        // contract returns void and upstream clients no-op here too;
        // pretending otherwise would be a fake implementation.
        Log.d(TAG, "clearDNSCache: no platform API, no-op")
    }

    // -- PlatformInterface: connection owner ---------------------------

    override fun useProcFS(): Boolean = false

    override fun findConnectionOwner(
        ipProtocol: Int, sourceAddress: String, sourcePort: Int,
        destinationAddress: String, destinationPort: Int,
    ): Int {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            // getConnectionOwnerUid exists from API 29 and useProcFS
            // is false, so below 29 there is no honest answer.
            throw UnsupportedOperationException("connection owner lookup requires API 29+")
        }
        return connectivity.getConnectionOwnerUid(
            ipProtocol,
            InetSocketAddress(sourceAddress, sourcePort),
            InetSocketAddress(destinationAddress, destinationPort),
        )
    }

    override fun packageNameByUid(uid: Int): String =
        packageManager.getPackagesForUid(uid)?.firstOrNull()
            ?: throw PackageManager.NameNotFoundException("no package for uid $uid")

    override fun uidByPackageName(packageName: String): Int =
        packageManager.getApplicationInfo(packageName, 0).uid

    // -- PlatformInterface: interface monitor ----------------------------

    override fun startDefaultInterfaceMonitor(listener: InterfaceUpdateListener) {
        if (monitorCallback != null) return
        monitorListener = listener
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) = notifyDefaultInterface()
            override fun onLost(network: Network) = notifyDefaultInterface()
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) = notifyDefaultInterface()
            override fun onLinkPropertiesChanged(network: Network, props: LinkProperties) = notifyDefaultInterface()
        }
        monitorCallback = callback
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            connectivity.registerDefaultNetworkCallback(callback)
        } else {
            connectivity.registerNetworkCallback(NetworkRequest.Builder().build(), callback)
        }
        notifyDefaultInterface()
    }

    override fun closeDefaultInterfaceMonitor(listener: InterfaceUpdateListener) {
        monitorCallback?.let { runCatching { connectivity.unregisterNetworkCallback(it) } }
        monitorCallback = null
        monitorListener = null
    }

    private fun notifyDefaultInterface() {
        val listener = monitorListener ?: return
        val network = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) connectivity.activeNetwork else null
        val props = network?.let { connectivity.getLinkProperties(it) }
        val caps = network?.let { connectivity.getNetworkCapabilities(it) }
        val name = props?.interfaceName
        if (network == null || name == null) {
            listener.updateDefaultInterface("", -1, false, false)
            return
        }
        val index = runCatching { java.net.NetworkInterface.getByName(name)?.index ?: -1 }.getOrDefault(-1)
        val metered = caps?.let { !it.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) } ?: false
        listener.updateDefaultInterface(name, index, metered, false)
    }

    // -- PlatformInterface: interfaces -----------------------------------

    override fun getInterfaces(): NetworkInterfaceIterator {
        // Link/capability facts per interface name from ConnectivityManager.
        val byName = HashMap<String, Triple<List<String>, Int, Boolean>>()
        for (network in connectivity.allNetworks) {
            val props = connectivity.getLinkProperties(network) ?: continue
            val name = props.interfaceName ?: continue
            val caps = connectivity.getNetworkCapabilities(network)
            val type = when {
                caps == null -> Libbox.InterfaceTypeOther
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> Libbox.InterfaceTypeWIFI
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> Libbox.InterfaceTypeCellular
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> Libbox.InterfaceTypeEthernet
                else -> Libbox.InterfaceTypeOther
            }
            val dns = props.dnsServers.mapNotNull { it.hostAddress }
            val metered = caps?.let { !it.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) } ?: false
            byName[name] = Triple(dns, type, metered)
        }

        val result = ArrayList<LibboxInterface>()
        val interfaces = java.net.NetworkInterface.getNetworkInterfaces() ?: return ListNetworkInterfaceIterator(result)
        for (netIf in interfaces) {
            if (!netIf.isUp) continue
            val addresses = netIf.interfaceAddresses.map { address ->
                "${address.address.hostAddress}/${address.networkPrefixLength}"
            }
            var flags = 0
            if (netIf.isUp) flags = flags or IFF_UP or IFF_RUNNING
            if (netIf.isLoopback) flags = flags or IFF_LOOPBACK
            if (netIf.isPointToPoint) flags = flags or IFF_POINTOPOINT
            if (netIf.supportsMulticast()) flags = flags or IFF_MULTICAST
            val extra = byName[netIf.name]
            val item = LibboxInterface()
            item.setIndex(runCatching { netIf.index }.getOrDefault(-1))
            item.setMTU(runCatching { netIf.mtu }.getOrDefault(0))
            item.setName(netIf.name)
            item.setAddresses(ListStringIterator(addresses))
            item.setFlags(flags)
            item.setType(extra?.second ?: Libbox.InterfaceTypeOther)
            item.setDNSServer(ListStringIterator(extra?.first ?: emptyList()))
            item.setMetered(extra?.third ?: false)
            result += item
        }
        return ListNetworkInterfaceIterator(result)
    }

    // -- PlatformInterface: misc -----------------------------------------

    override fun underNetworkExtension(): Boolean = false

    override fun includeAllNetworks(): Boolean = false

    override fun readWIFIState(): io.nekohasekai.libbox.WIFIState? {
        val wifi = getSystemService(WifiManager::class.java) ?: return null
        @Suppress("DEPRECATION") val info = wifi.connectionInfo ?: return null
        val ssid = info.ssid?.removeSurrounding("\"") ?: return null
        if (ssid.isBlank() || ssid == "<unknown ssid>") return null
        val bssid = info.bssid ?: ""
        if (bssid == "02:00:00:00:00:00") return Libbox.newWIFIState(ssid, "")
        return Libbox.newWIFIState(ssid, bssid)
    }

    override fun systemCertificates(): StringIterator {
        val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        factory.init(null as KeyStore?)
        val trustManager = factory.trustManagers.filterIsInstance<X509TrustManager>().firstOrNull()
            ?: return ListStringIterator(emptyList())
        val pem = trustManager.acceptedIssuers.map { cert ->
            val body = Base64.encodeToString(cert.encoded, Base64.NO_WRAP)
            "-----BEGIN CERTIFICATE-----\n$body\n-----END CERTIFICATE-----"
        }
        return ListStringIterator(pem)
    }

    override fun sendNotification(notification: LibboxNotification) {
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ALERTS)
        } else {
            @Suppress("DEPRECATION") Notification.Builder(this)
        }
        val built = builder
            .setContentTitle(notification.getTitle()?.takeIf { it.isNotBlank() } ?: getString(R.string.app_name))
            .setContentText(notification.getBody() ?: "")
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .build()
        notifications.notify(ALERT_NOTIFICATION_ID, built)
    }

    override fun writeLog(message: String) {
        Log.d(TAG, message)
        VpnState.appendLog(message)
    }

    companion object {
        const val ACTION_START = "one.levvs.sora.legacy.action.START"
        const val ACTION_STOP = "one.levvs.sora.legacy.action.STOP"
        private const val TAG = "SoraVpnService"
        private const val CONFIG_FILE = "config.json"
        private const val NOTIFICATION_ID = 1
        private const val ALERT_NOTIFICATION_ID = 2
        private const val CHANNEL_VPN = "vpn-status"
        private const val CHANNEL_ALERTS = "engine-alerts"

        // net/if.h bits, as libbox's link_flags_unix.go maps them.
        private const val IFF_UP = 0x1
        private const val IFF_LOOPBACK = 0x8
        private const val IFF_POINTOPOINT = 0x10
        private const val IFF_RUNNING = 0x40
        private const val IFF_MULTICAST = 0x1000
    }
}
