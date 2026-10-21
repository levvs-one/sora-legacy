import UIKit
import SoraLegacyCore

/// Settings: local port, TUN MTU, strict route (the same three
/// knobs Android's ServerStore exposes), plus the engine catalog
/// from mobileapi.EngineInfo rendered as data, not prose.
final class SettingsViewController: UITableViewController {
    private var info = EngineInfo(engines: [], defaultPreference: [])

    override func viewDidLoad() {
        super.viewDidLoad()
        title = "Settings"
        info = AppStore.mobileAPI.engineInfo()
    }

    override func numberOfSections(in tableView: UITableView) -> Int { 2 }
    override func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        section == 0 ? "Tunnel" : "Engines (mobileapi.EngineInfo)"
    }
    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        section == 0 ? 3 : max(info.engines.count, 1)
    }

    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "setting") ??
            UITableViewCell(style: .value1, reuseIdentifier: "setting")
        let store = AppStore.shared
        if indexPath.section == 0 {
            switch indexPath.row {
            case 0:
                cell.textLabel?.text = "Local port (mixed inbound)"
                cell.detailTextLabel?.text = "\(store.localPort())"
            case 1:
                cell.textLabel?.text = "TUN MTU"
                cell.detailTextLabel?.text = "\(store.tunMTU())"
            default:
                cell.textLabel?.text = "Strict route"
                cell.detailTextLabel?.text = store.strictRoute() ? "On" : "Off"
            }
            cell.accessoryType = .disclosureIndicator
        } else if info.engines.isEmpty {
            cell.textLabel?.text = "Mobileapi framework not linked"
            cell.detailTextLabel?.text = nil
            cell.accessoryType = .none
        } else {
            let engine = info.engines[indexPath.row]
            cell.textLabel?.text = engine.kind
            cell.detailTextLabel?.text = "≥ \(engine.minVersion) · \(engine.protocols.count) protocols"
            cell.accessoryType = .none
        }
        return cell
    }

    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)
        guard indexPath.section == 0 else { return }
        let store = AppStore.shared
        switch indexPath.row {
        case 0: editNumber(title: "Local port", current: store.localPort()) { store.setLocalPort($0); tableView.reloadData() }
        case 1: editNumber(title: "TUN MTU", current: store.tunMTU()) { store.setTunMTU($0); tableView.reloadData() }
        default:
            store.setStrictRoute(!store.strictRoute())
            tableView.reloadData()
        }
    }

    private func editNumber(title: String, current: Int, apply: @escaping (Int) -> Void) {
        let alert = UIAlertController(title: title, message: nil, preferredStyle: .alert)
        alert.addTextField {
            $0.text = "\(current)"
            $0.keyboardType = .numberPad
        }
        alert.addAction(UIAlertAction(title: "Save", style: .default) { _ in
            if let text = alert.textFields?.first?.text, let value = Int(text), value > 0 {
                apply(value)
            }
        })
        alert.addAction(UIAlertAction(title: "Cancel", style: .cancel))
        present(alert, animated: true)
    }
}
