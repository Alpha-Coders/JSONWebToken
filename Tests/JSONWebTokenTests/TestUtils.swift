//
//  TestUtils.swift
//  JSONWebToken
//
//  Created by Antoine Palazzolo on 19/11/15.
//

import Foundation
import JSONWebToken

func testDataURL(name: String, extension: String) -> URL {
    if Bundle(identifier: "com.kreactive.JSONWebToken") != nil {
        return Bundle(for: HMACTests.self).url(forResource: name, withExtension: `extension`)!
    } else {
        let directory = URL(fileURLWithPath: #file).deletingLastPathComponent().appendingPathComponent("Samples")
        return directory.appendingPathComponent("\(name).\(`extension`)")
    }
}
func ReadRawSampleWithName(_ name: String) -> String {
    let url = testDataURL(name: name, extension: "jwt")
    return try! String(contentsOf: url, encoding: .utf8)
}
func ReadSampleWithName(_ name : String) -> JSONWebToken {
    return try! JSONWebToken(string : ReadRawSampleWithName(name))
}

var SamplePublicKey : RSAKey = {
    return SampleIdentity.publicKey

}()

let SamplePrivateKey : RSAKey = {
    return SampleIdentity.privateKey
}()

let SampleIdentity : (publicKey: RSAKey, privateKey: RSAKey) = {
    let p12Data = try! Data(contentsOf: testDataURL(name: "identity", extension: "p12"))
    return try! RSAKey.keysFromPkcs12Identity(p12Data, passphrase : "1234")
}()

let SamplePayload : JSONWebToken.Payload = {
    var payload = JSONWebToken.Payload()
    payload.issuer = "1234567890"
    payload["name"] = "John Doe"
    return payload
}()
