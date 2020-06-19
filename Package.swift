// swift-tools-version:5.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "JSONWebToken",
    platforms: [
        .iOS(.v12), .tvOS(.v12)
    ],
    products: [
        .library(name: "JSONWebToken", targets: ["JSONWebToken"]),
    ],
    dependencies: [
    ],
    targets: [
        .target(name: "JSONWebToken", dependencies: []),
        .testTarget(name: "JSONWebTokenTests", dependencies: ["JSONWebToken"]),
    ]
)
