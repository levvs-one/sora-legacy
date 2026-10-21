import UIKit
import SoraLegacyCore

/// Servers screen: list + selection + delete, and import by
/// pasting share links or a subscription URL (fetched with
/// URLSession; the body goes to mobileapi.parseSubscription —
/// fetching stays the client's job, mobileapi.go is explicit).
final class ServersViewController: UITableViewController {
    private var servers: [Server] = []

    override func viewDidLoad() {
        super.viewDidLoad()
        title = "Servers"
        navigationItem.rightBarButtonItem = UIBarButtonItem(
            barButtonSystemItem: .add, target: self, action: #selector(importTapped))
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        reload()
    }

    private func reload() {
        servers = AppStore.shared.servers()
        tableView.reloadData()
    }

    // MARK: Table

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        servers.count
    }

    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "server") ??
            UITableViewCell(style: .subtitle, reuseIdentifier: "server")
        let server = servers[indexPath.row]
        cell.textLabel?.text = server.label
        cell.detailTextLabel?.text = "\(server.protocol) · \(server.server):\(server.port)"
        cell.accessoryType = AppStore.shared.selectedID() == server.id ? .checkmark : .none
        return cell
    }

    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        AppStore.shared.select(id: servers[indexPath.row].id)
        tableView.reloadData()
        tableView.deselectRow(at: indexPath, animated: true)
    }

    override func tableView(_ tableView: UITableView,
                            commit editingStyle: UITableViewCell.EditingStyle,
                            forRowAt indexPath: IndexPath) {
        if editingStyle == .delete {
            AppStore.shared.removeServer(id: servers[indexPath.row].id)
            reload()
        }
    }

    // MARK: Import

    @objc private func importTapped() {
        let sheet = UIAlertController(title: "Import", message: nil, preferredStyle: .actionSheet)
        sheet.addAction(UIAlertAction(title: "Paste links", style: .default) { _ in self.promptPaste(links: true) })
        sheet.addAction(UIAlertAction(title: "Paste subscription content", style: .default) { _ in self.promptPaste(links: false) })
        sheet.addAction(UIAlertAction(title: "Fetch subscription URL", style: .default) { _ in self.promptURL() })
        sheet.addAction(UIAlertAction(title: "Cancel", style: .cancel))
        present(sheet, animated: true)
    }

    private func promptPaste(links: Bool) {
        prompt(title: links ? "Paste share links" : "Paste subscription",
               placeholder: links ? "vless://… (one per line)" : "Subscription body") { [weak self] text in
            guard let self, let text, !text.isEmpty else { return }
            self.runImport {
                if links { return try AppStore.mobileAPI.importLinks(text) }
                return try AppStore.mobileAPI.parseSubscription(Data(text.utf8))
            }
        }
    }

    private func promptURL() {
        prompt(title: "Subscription URL", placeholder: "https://…") { [weak self] text in
            guard let self, let text, let url = URL(string: text) else { return }
            var request = URLRequest(url: url)
            request.timeoutInterval = 30
            URLSession.shared.dataTask(with: request) { [weak self] data, _, error in
                guard let self else { return }
                if let error { self.showError(error.localizedDescription); return }
                guard let data else { self.showError("Empty response"); return }
                self.runImport { try AppStore.mobileAPI.parseSubscription(data) }
            }.resume()
        }
    }

    private func runImport(_ work: @escaping () throws -> [Server]) {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            do {
                let imported = try work()
                DispatchQueue.main.async {
                    AppStore.shared.addServers(imported)
                    if AppStore.shared.selectedID() == nil, let first = imported.first {
                        AppStore.shared.select(id: first.id)
                    }
                    self?.reload()
                }
            } catch {
                DispatchQueue.main.async { self?.showError("\(error)") }
            }
        }
    }

    private func prompt(title: String, placeholder: String, done: @escaping (String?) -> Void) {
        let alert = UIAlertController(title: title, message: nil, preferredStyle: .alert)
        alert.addTextField { $0.placeholder = placeholder }
        alert.addAction(UIAlertAction(title: "Import", style: .default) { _ in
            done(alert.textFields?.first?.text)
        })
        alert.addAction(UIAlertAction(title: "Cancel", style: .cancel) { _ in done(nil) })
        present(alert, animated: true)
    }

    private func showError(_ message: String) {
        let alert = UIAlertController(title: "Import failed", message: message, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "OK", style: .default))
        present(alert, animated: true)
    }
}
