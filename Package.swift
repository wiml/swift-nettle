// swift-tools-version:5.0

import PackageDescription

let package = Package(
    name: "Nettle",
    products: [
        .library(name: "Nettle", targets: ["Nettle"]),
    ],
    dependencies: [
        .package(url: "https://github.com/Ponyboy47/ErrNo", .upToNextMinor(from: "0.5.2"))
    ],
    targets: [
        .systemLibrary(
	  name: "CNettle",
          path: "src/libnettle",
          pkgConfig: "nettle",
          providers: [.apt(["nettle-dev"])]),
	.target(
          name: "Nettle",
          dependencies: [
            "CNettle",
            "ErrNo"
          ],
          path: "src/swift"),
        .testTarget(
          name: "NettleTests",
          dependencies: ["Nettle"],
          path: "src/tests"),
    ]
)
