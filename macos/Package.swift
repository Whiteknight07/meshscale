// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "meshscale",
    platforms: [.macOS(.v14)],
    products: [.executable(name: "meshscale-menu", targets: ["MeshscaleApp"])],
    targets: [
        .target(name: "MeshscaleCore"),
        .executableTarget(name: "MeshscaleApp", dependencies: ["MeshscaleCore"], resources: [.process("Resources")]),
        .testTarget(name: "MeshscaleCoreTests", dependencies: ["MeshscaleCore", "MeshscaleApp"], resources: [.copy("Fixtures")])
    ]
)
