package one.levvs.sora.legacy

import android.app.Activity
import android.app.AlertDialog
import android.os.Bundle
import android.widget.ArrayAdapter
import android.widget.EditText
import android.widget.ListView
import mobileapi.Mobileapi
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.Executors

/**
 * Server list from the imported documents, plus the three import
 * paths mobileapi supports:
 *  - pasted share links / text        -> Mobileapi.importLinks
 *  - pasted subscription body         -> Mobileapi.parseSubscription
 *  - subscription URL fetched here    -> body -> Mobileapi.parseSubscription
 * Fetching lives in the client by design (mobileapi never touches
 * the network). Imports run on a worker thread; gomobile calls block.
 */
class ServersActivity : Activity() {

    private lateinit var store: ServerStore
    private lateinit var listView: ListView
    private lateinit var pasteInput: EditText
    private lateinit var urlInput: EditText
    private val executor = Executors.newSingleThreadExecutor()
    private var entries: List<ServerEntry> = emptyList()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        go.Seq.setContext(applicationContext)
        store = ServerStore(this)

        val column = contentColumn()
        column.label("Imported servers (tap to select, long-press to delete)", 14f)
        listView = ListView(this)
        column.addView(listView, android.widget.LinearLayout.LayoutParams(
            android.view.ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))

        column.label("Import links or subscription text", 14f)
        pasteInput = column.input("Paste vless://… / trojan://… links, a subscription body, a Clash or sing-box document", multiLine = true)
        column.button("Import links") { runImport { Mobileapi.importLinks(pasteInput.text.toString()) } }
        column.button("Import as subscription document") {
            runImport { Mobileapi.parseSubscription(pasteInput.text.toString().toByteArray(Charsets.UTF_8)) }
        }

        column.label("Subscription URL", 14f)
        urlInput = column.input("https://provider.example/sub/…")
        column.button("Fetch subscription") { fetchSubscription() }

        listView.setOnItemClickListener { _, _, position, _ ->
            val entry = entries.getOrNull(position) ?: return@setOnItemClickListener
            store.select(entry.id)
            refresh()
            toast("Selected: ${entry.label()}")
        }
        listView.setOnItemLongClickListener { _, _, position, _ ->
            val entry = entries.getOrNull(position) ?: return@setOnItemLongClickListener false
            AlertDialog.Builder(this)
                .setTitle("Delete server")
                .setMessage(entry.label())
                .setPositiveButton("Delete") { _, _ ->
                    store.delete(entry.id)
                    refresh()
                }
                .setNegativeButton("Cancel", null)
                .show()
            true
        }
        refresh()
    }

    override fun onDestroy() {
        executor.shutdown()
        super.onDestroy()
    }

    private fun refresh() {
        entries = store.loadServers()
        val selectedId = store.selectedId()
        val labels = entries.map { entry ->
            (if (entry.id == selectedId) "● " else "○ ") + entry.label()
        }
        listView.adapter = ArrayAdapter(this, android.R.layout.simple_list_item_1, labels)
    }

    private fun runImport(block: () -> String) {
        executor.execute {
            try {
                val merged = store.mergeImport(block())
                runOnUiThread {
                    refresh()
                    toast("Imported. ${merged.size} server(s) stored.")
                }
            } catch (e: Exception) {
                runOnUiThread { toast("Import failed: ${shortError(e)}") }
            }
        }
    }

    private fun fetchSubscription() {
        val raw = urlInput.text.toString().trim()
        if (raw.isEmpty()) {
            toast("Enter a subscription URL first.")
            return
        }
        executor.execute {
            try {
                val body = httpGet(raw)
                val merged = store.mergeImport(Mobileapi.parseSubscription(body))
                runOnUiThread {
                    refresh()
                    toast("Subscription imported. ${merged.size} server(s) stored.")
                }
            } catch (e: Exception) {
                runOnUiThread { toast("Subscription failed: ${shortError(e)}") }
            }
        }
    }

    /** Plain HttpURLConnection fetch. On a device this is ordinary
     *  app traffic; cleartext http:// URLs are refused by the
     *  manifest's usesCleartextTraffic=false and surface here as an
     *  error, which is the honest outcome. */
    private fun httpGet(rawUrl: String): ByteArray {
        val connection = URL(rawUrl).openConnection() as HttpURLConnection
        return try {
            connection.connectTimeout = 15_000
            connection.readTimeout = 30_000
            connection.instanceFollowRedirects = true
            connection.setRequestProperty("User-Agent", "SoraLegacy-Android/0.1")
            val code = connection.responseCode
            if (code !in 200..299) throw IllegalStateException("server answered HTTP $code")
            connection.inputStream.use { it.readBytes() }
        } finally {
            connection.disconnect()
        }
    }

    private fun shortError(e: Exception): String =
        e.message?.takeIf { it.isNotBlank() } ?: e.javaClass.simpleName
}
