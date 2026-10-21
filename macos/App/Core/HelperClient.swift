import Foundation

/// Runs the `sora-ctl` helper and decodes its JSON.
///
/// The helper (macos/helper, Go) is the only part of the client that
/// speaks to the daemon: JSON-RPC over the unix socket, Handshake,
/// control token — all of it lives there, tested there. This class is
/// deliberately a dumb process runner: build argv, read stdout as one
/// JSON document, map a non-zero exit to the helper's {"error": ...}
/// on stderr. No retries and no caching: the UI polls `status`
/// explicitly and every answer it shows is fresh.
public final class HelperClient {
    public enum Failure: Error, Equatable {
        case helperMissing(String)
        case helperFailed(String)
        case unreadableOutput
    }

    /// Path of the helper binary. Installed layout:
    /// /usr/local/lib/sora-legacy/sora-ctl (next to the daemon).
    /// Inside the app bundle a copy may live in Contents/Helpers;
    /// the bundle location wins when present.
    public let helperPath: String

    public init(helperPath: String? = nil) {
        if let helperPath = helperPath {
            self.helperPath = helperPath
        } else if let bundled = Bundle.main.path(forAuxiliaryExecutable: "sora-ctl") {
            self.helperPath = bundled
        } else {
            self.helperPath = "/usr/local/lib/sora-legacy/sora-ctl"
        }
    }

    /// Runs one command synchronously and decodes stdout as `T`.
    /// Callers run it off the main queue; the helper is short-lived
    /// (one daemon round-trip per command at most).
    public func run<T: Decodable>(_ type: T.Type, arguments: [String],
                                  stdin: String? = nil) -> Result<T, Failure> {
        guard FileManager.default.isExecutableFile(atPath: helperPath) else {
            return .failure(.helperMissing(helperPath))
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: helperPath)
        process.arguments = arguments
        let outPipe = Pipe()
        let errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe
        if stdin != nil {
            process.standardInput = Pipe()
        }
        do {
            try process.run()
        } catch {
            return .failure(.helperFailed("\(error)"))
        }
        if let stdin = stdin, let input = process.standardInput as? Pipe {
            input.fileHandleForWriting.write(stdin.data(using: .utf8) ?? Data())
            try? input.fileHandleForWriting.close()
        }
        process.waitUntilExit()
        let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
        if process.terminationStatus != 0 {
            let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
            if let doc = try? JSONDecoder().decode(HelperError.self, from: errData) {
                return .failure(.helperFailed(doc.error))
            }
            let text = String(data: errData, encoding: .utf8) ?? ""
            return .failure(.helperFailed(text.isEmpty ? "exit \(process.terminationStatus)" : text))
        }
        do {
            return .success(try JSONDecoder().decode(type, from: outData))
        } catch {
            return .failure(.unreadableOutput)
        }
    }

    // MARK: Typed commands (argv mirrors macos/helper's CLI contract)

    public func status() -> Result<HelperStatus, Failure> {
        return run(HelperStatus.self, arguments: ["status"])
    }

    public func servers() -> Result<ServersDocument, Failure> {
        return run(ServersDocument.self, arguments: ["servers"])
    }

    public func engineInfo() -> Result<EngineCatalog, Failure> {
        return run(EngineCatalog.self, arguments: ["engineinfo"])
    }

    public func importLinks(_ payload: String) -> Result<ServersDocument, Failure> {
        return run(ServersDocument.self, arguments: ["import"], stdin: payload)
    }

    public func importSubscription(url: String) -> Result<ServersDocument, Failure> {
        return run(ServersDocument.self, arguments: ["import-url", url])
    }

    public func select(id: String) -> Result<ServersDocument, Failure> {
        // The helper answers {"selected": id}; decode leniently via
        // ServersDocument-compatible shape is not guaranteed, so this
        // call uses a tiny local shape.
        struct Selected: Decodable { var selected: String }
        switch run(Selected.self, arguments: ["select", id]) {
        case .success(let s):
            return .success(ServersDocument(servers: [], selected: s.selected, source: nil))
        case .failure(let f):
            return .failure(f)
        }
    }

    public func connect(id: String, mode: String, killSwitch: Bool) -> Result<HelperStatus, Failure> {
        var args = ["connect", "--mode", mode, "--id", id]
        if killSwitch { args.append("--kill-switch") }
        return run(HelperStatus.self, arguments: args)
    }

    public func disconnect() -> Result<HelperStatus, Failure> {
        return run(HelperStatus.self, arguments: ["disconnect"])
    }
}
