import Foundation

#if canImport(Mobileapi)
import Mobileapi

/// The real client over the gomobile-generated `Mobileapi`
/// framework. Compiled only where the framework is linked (the app
/// target on a Mac — BUILD-MAC.md); on Linux this whole file is
/// inert, which is what keeps `swift test` framework-free.
///
/// Generated-name convention (official gomobile, as used for the
/// Android AAR where the class is `mobileapi.Mobileapi`): package
/// functions become `Mobileapi<Name>` in Swift, `(String, error)`
/// Go returns become a throwing Swift function, `[]byte` becomes
/// `Data`, and a no-error `string` return stays a plain String.
///
/// TODO(verify-on-mac): reconcile each call below against
/// Mobileapi.xcframework's generated `Mobileapi.h` after the bind
/// (BUILD-MAC.md §2) — gomobile's exact Swift spellings (e.g. whether
/// the bytes parameter is `Data` or `NSData`) are a header fact, not
/// something this Linux tree can check.
public struct GeneratedMobileAPI: MobileAPI {
    public init() {}

    public func importLinks(_ text: String) throws -> [Server] {
        // Go: ImportLinks(text string) (string, error)
        let json = try MobileapiImportLinks(text)
        return try MobileAPIJSON.decodeServers(json)
    }

    public func parseSubscription(_ body: Data) throws -> [Server] {
        // Go: ParseSubscription(body []byte) (string, error)
        let json = try MobileapiParseSubscription(body)
        return try MobileAPIJSON.decodeServers(json)
    }

    public func buildPlan(_ plan: PlanDocument) throws -> PlanDocument {
        // Go: BuildPlan(credentialJSON string) (string, error)
        let json = try MobileapiBuildPlan(MobileAPIJSON.encodePlan(plan))
        return try MobileAPIJSON.decodePlan(json)
    }

    public func renderSingBoxConfig(_ plan: PlanDocument) throws -> String {
        // Go: RenderSingBoxConfig(credentialJSON string) (string, error)
        try MobileapiRenderSingBoxConfig(MobileAPIJSON.encodePlan(plan))
    }

    public func engineInfo() -> EngineInfo {
        // Go: EngineInfo() string — no error return.
        MobileAPIJSON.decodeEngineInfo(MobileapiEngineInfo())
    }
}
#endif
