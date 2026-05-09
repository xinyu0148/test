// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "PhishGuardSLMBatch",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "PhishGuardSLMBatch", targets: ["PhishGuardSLMBatch"])
    ],
    targets: [
        .executableTarget(
            name: "PhishGuardSLMBatch"
        )
    ]
)

