// swift-tools-version:5.0

import PackageDescription

let package = Package(
    name: "Nettle",
    products: [
        .library(name: "Nettle", targets: ["Nettle"]),
    ],
    targets: [
        .systemLibrary(
	  name: "CNettle",
          path: "src/libnettle",
          pkgConfig: "nettle",
          providers: [.apt(["nettle-dev"])]),
	.target(
          name: "Nettle",
          dependencies: ["CNettle"],
          path: "src/swift"),
        .testTarget(
          name: "NettleTests",
          dependencies: ["Nettle"],
          path: "src/tests"),
    ]
)
