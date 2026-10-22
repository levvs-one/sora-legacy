package one.levvs.sora.legacy

import android.app.Activity
import android.app.AlertDialog
import android.os.Bundle
import android.util.Log
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
        column.label(getString(R.string.imported_servers_hint), 14f)
        listView = ListView(this)
        column.addView(listView, android.widget.LinearLayout.LayoutParams(
            android.view.ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))

        column.label(getString(R.string.import_text_label), 14f)
        pasteInput = column.input(getString(R.string.import_input_hint), multiLine = true)
        column.button(getString(R.string.import_links_button)) { runImport { Mobileapi.importLinks(pasteInput.text.toString()) } }
        column.button(getString(R.string.import_subscription_button)) {
            runImport { Mobileapi.parseSubscription(pasteInput.text.toString().toByteArray(Charsets.UTF_8)) }
        }

        column.label(getString(R.string.subscription_url_label), 14f)
        urlInput = column.input(getString(R.string.subscription_url_hint))
        column.button(getString(R.string.fetch_subscription_button)) { fetchSubscription() }

        listView.setOnItemClickListener { _, _, position, _ ->
            val entry = entries.getOrNull(position) ?: return@setOnItemClickListener
            store.select(entry.id)
            refresh()
            toast(getString(R.string.selected_toast, entry.label()))
        }
        listView.setOnItemLongClickListener { _, _, position, _ ->
            val entry = entries.getOrNull(position) ?: return@setOnItemLongClickListener false
            AlertDialog.Builder(this)
                .setTitle(getString(R.string.delete_server_title))
                .setMessage(entry.label())
                .setPositiveButton(getString(R.string.delete_button)) { _, _ ->
                    store.delete(entry.id)
                    refresh()
                }
                .setNegativeButton(getString(R.string.cancel_button), null)
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
                    toast(getString(R.string.imported_toast, merged.size))
                }
            } catch (e: Exception) {
                Log.w(TAG, "import failed", e)
                runOnUiThread { toast(getString(R.string.import_failed_toast)) }
            }
        }
    }

    private fun fetchSubscription() {
        val raw = urlInput.text.toString().trim()
        if (raw.isEmpty()) {
            toast(getString(R.string.enter_url_toast))
            return
        }
        executor.execute {
            try {
                val body = httpGet(raw)
                val merged = store.mergeImport(Mobileapi.parseSubscription(body))
                runOnUiThread {
                    refresh()
                    toast(getString(R.string.subscription_imported_toast, merged.size))
                }
            } catch (e: Exception) {
                Log.w(TAG, "subscription fetch/import failed", e)
                runOnUiThread { toast(getString(R.string.subscription_failed_toast)) }
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

    companion object {
        private const val TAG = "ServersActivity"
    }
}
