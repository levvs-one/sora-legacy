package one.levvs.sora.legacy

import java.util.concurrent.CopyOnWriteArrayList

/** Connection lifecycle as the UI shows it. */
enum class ConnState { STOPPED, STARTING, RUNNING, STOPPING, ERROR }

/**
 * Process-local view of the VPN service state. The service and the
 * activities live in the same process (no android:process split in
 * the manifest), so a plain in-memory holder is the honest channel:
 * no IPC, no stale persisted "connected" flag after a process death.
 */
object VpnState {
    @Volatile var state: ConnState = ConnState.STOPPED
        private set
    @Volatile var serverName: String = ""
        private set
    @Volatile var lastError: String = ""
        private set
    @Volatile var sinceMillis: Long = 0L
        private set

    /** Last engine log lines (libbox WriteLog), newest last. */
    private val logRing = ArrayDeque<String>()
    private const val LOG_RING_MAX = 100

    private val listeners = CopyOnWriteArrayList<() -> Unit>()

    fun addListener(listener: () -> Unit) { listeners += listener }
    fun removeListener(listener: () -> Unit) { listeners -= listener }

    fun transition(next: ConnState, server: String = serverName, error: String = "") {
        state = next
        serverName = server
        lastError = error
        sinceMillis = if (next == ConnState.RUNNING) System.currentTimeMillis() else sinceMillis
        for (listener in listeners) listener()
    }

    @Synchronized fun appendLog(line: String) {
        if (logRing.size >= LOG_RING_MAX) logRing.removeFirst()
        logRing.addLast(line)
    }

    @Synchronized fun recentLog(): List<String> = logRing.toList()
}
