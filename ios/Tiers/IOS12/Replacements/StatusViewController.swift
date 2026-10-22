import UIKit
import SoraLegacyCore

/// TIER-iOS12 REPLACEMENT for `App/StatusViewController.swift`.
///
/// Used ONLY by the iOS 12 tier variant (`project-ios12.yml`
/// excludes the App/ original and compiles this file instead) —
/// the main tree's file-replacement pattern for tier deltas.
///
/// Delta against the original: exactly two lines, both semantic
/// colors that exist only on iOS 13+ (`UIColor.systemBackground`,
/// `UIColor.secondaryLabel`). Each is gated with `#available` and
/// falls back to the pre-dark-mode equivalents (`.white` / `.gray`)
/// — iOS 12 has no dark mode, so the fallbacks are the same colors
/// the 13+ system colors resolve to in light mode. Everything else
/// is byte-identical to the original; if the original changes,
/// this file must be re-derived (TARGET-NOTES §4).
final class StatusViewController: UIViewController {
    private let tunnel = TunnelManager()
    private let statusLabel = UILabel()
    private let serverLabel = UILabel()
    private let toggleButton = UIButton(type: .system)

    override func viewDidLoad() {
        super.viewDidLoad()
        title = "Sora Legacy"
        if #available(iOS 13.0, *) {
            view.backgroundColor = .systemBackground
        } else {
            view.backgroundColor = .white
        }
        statusLabel.font = .preferredFont(forTextStyle: .title2)
        statusLabel.textAlignment = .center
        serverLabel.font = .preferredFont(forTextStyle: .body)
        serverLabel.textAlignment = .center
        if #available(iOS 13.0, *) {
            serverLabel.textColor = .secondaryLabel
        } else {
            serverLabel.textColor = .gray
        }
        toggleButton.titleLabel?.font = .preferredFont(forTextStyle: .headline)
        toggleButton.addTarget(self, action: #selector(toggle), for: .touchUpInside)
        let stack = UIStackView(arrangedSubviews: [statusLabel, serverLabel, toggleButton])
        stack.axis = .vertical
        stack.spacing = 16
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 24),
            stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -24),
        ])
        tunnel.onChange = { [weak self] in self?.render() }
        tunnel.load()
        render()
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        render()
    }

    private func render() {
        let selected = AppStore.shared.selected()
        serverLabel.text = selected?.label ?? "No server imported yet"
        switch tunnel.state {
        case .running:
            statusLabel.text = "Connected"
            toggleButton.setTitle("Disconnect", for: .normal)
        case .starting:
            statusLabel.text = "Connecting…"
            toggleButton.setTitle("Cancel", for: .normal)
        case .stopping:
            statusLabel.text = "Disconnecting…"
            toggleButton.setTitle("Disconnect", for: .normal)
        case .error:
            statusLabel.text = tunnel.lastError ?? "Error"
            toggleButton.setTitle("Connect", for: .normal)
        case .stopped:
            statusLabel.text = "Disconnected"
            toggleButton.setTitle("Connect", for: .normal)
        }
        toggleButton.isEnabled = tunnel.state != .stopping
    }

    @objc private func toggle() {
        if tunnel.state == .running || tunnel.state == .starting {
            tunnel.disconnect()
        } else {
            tunnel.connect()
        }
    }
}
