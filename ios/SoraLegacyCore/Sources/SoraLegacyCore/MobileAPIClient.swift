import Foundation

/// The seam over the generated `Mobileapi` xcframework (gomobile bind
/// of core/mobileapi — see ../BUILD-MAC.md). Every method mirrors one
/// exported Go function of mobileapi.go, name for name:
///
///   ImportLinks(text) (string, error)
///   ParseSubscription(body []byte) (string, error)
///   BuildPlan(credentialJSON) (string, error)
///   RenderSingBoxConfig(credentialJSON) (string, error)
///   EngineInfo() string
///
/// App and tests depend on this protocol only; the generated binding
/// is confined to `GeneratedMobileAPI` (MobileAPIGenerated.swift).
public protocol MobileAPI {
    func importLinks(_ text: String) throws -> [Server]
    func parseSubscription(_ body: Data) throws -> [Server]
    func buildPlan(_ plan: PlanDocument) throws -> PlanDocument
    func renderSingBoxConfig(_ plan: PlanDocument) throws -> String
    func engineInfo() -> EngineInfo
}

public enum MobileAPIError: Error, Equatable {
    case engine(String)
    case badJSON(String)
}

/// JSON coding shared by every MobileAPI implementation — the wire
/// shapes are mobileapi's, and both the generated client and test
/// fakes must agree on them byte for byte in structure.
public enum MobileAPIJSON {
    public static func decodeServers(_ json: String) throws -> [Server] {
        guard let data = json.data(using: .utf8) else { throw MobileAPIError.badJSON("not UTF-8") }
        do { return try JSONDecoder().decode([Server].self, from: data) }
        catch { throw MobileAPIError.badJSON("server array: \(error.localizedDescription)") }
    }
    public static func encodePlan(_ plan: PlanDocument) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        do {
            let data = try encoder.encode(plan)
            return String(decoding: data, as: UTF8.self)
        } catch { throw MobileAPIError.badJSON("plan encode: \(error.localizedDescription)") }
    }
    public static func decodePlan(_ json: String) throws -> PlanDocument {
        guard let data = json.data(using: .utf8) else { throw MobileAPIError.badJSON("not UTF-8") }
        do { return try JSONDecoder().decode(PlanDocument.self, from: data) }
        catch { throw MobileAPIError.badJSON("plan: \(error.localizedDescription)") }
    }
    public static func decodeEngineInfo(_ json: String) -> EngineInfo {
        guard let data = json.data(using: .utf8),
              let info = try? JSONDecoder().decode(EngineInfo.self, from: data) else {
            return EngineInfo(engines: [], defaultPreference: [])
        }
        return info
    }
}
