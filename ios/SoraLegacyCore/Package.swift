// swift-tools-version:5.9
import PackageDescription

// Pure-Swift core of the sora-legacy iOS client: models, the TunConfig
// injection, the mobileapi client seam and the shared app<->extension
// store. Foundation only — no UIKit, no NetworkExtension, no generated
// framework — so it builds and tests on Linux (`swift test`) exactly
// as it does on a Mac. Code that needs Apple-only frameworks lives in
// the app / PacketTunnel targets of ../project.yml, never here.
let package = Package(
    name: "SoraLegacyCore",
    platforms: [.iOS(.v13)],
    products: [.library(name: "SoraLegacyCore", targets: ["SoraLegacyCore"])],
    targets: [
        .target(name: "SoraLegacyCore"),
        .testTarget(name: "SoraLegacyCoreTests", dependencies: ["SoraLegacyCore"]),
    ]
)
