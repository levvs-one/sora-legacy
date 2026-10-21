// swift-tools-version:5.9
import PackageDescription

// This package exists so the AppKit-free core of the client
// (App/Core: capabilities, models, helper client, system proxy,
// settings) can be type-checked and unit-tested without Xcode —
// including on a Linux Swift toolchain, which is how this tree was
// built and verified. The AppKit layer (App/UI) is NOT part of the
// package: it is compiled by the Xcode project (project.yml) on a Mac.
let package = Package(
    name: "SoraLegacyMacCore",
    platforms: [.macOS(.v10_13)],
    products: [.library(name: "SoraLegacyMacCore", targets: ["SoraLegacyMacCore"])],
    targets: [
        .target(name: "SoraLegacyMacCore", path: "App/Core"),
        .testTarget(name: "SoraLegacyMacCoreTests", dependencies: ["SoraLegacyMacCore"],
                    path: "Tests/CoreTests"),
    ]
)
