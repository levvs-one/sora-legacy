import UIKit
import SoraLegacyCore

/// Status screen: connection state, selected server, connect /
/// disconnect. Mirrors Android MainActivity's honest-state model —
/// the label shows exactly TunnelManager's state; on error it shows
/// TunnelManager's authored user sentence (raw engine text goes to
/// the log, never to this label), never a fake "connected".
final class StatusViewController: UIViewController {
    private let tunnel = TunnelManager()
    private let statusLabel = UILabel()
    private let serverLabel = UILabel()
    private let toggleButton = UIButton(type: .system)

    override func viewDidLoad() {
        super.viewDidLoad()
        title = "Sora Legacy"
        view.backgroundColor = .systemBackground
        statusLabel.font = .preferredFont(forTextStyle: .title2)
        statusLabel.textAlignment = .center
        serverLabel.font = .preferredFont(forTextStyle: .body)
        serverLabel.textAlignment = .center
        serverLabel.textColor = .secondaryLabel
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
            statusLabel.text = tunnel.lastError ?? "Connection failed"
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
