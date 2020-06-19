//
//  KeyUtilsTests.swift
//  JSONWebToken
//
//  Created by Antoine Palazzolo on 25/11/15.
//

import Foundation


@testable import JSONWebToken
import XCTest


private let keyBase64 = "MIICCgKCAgEApmlQ3ER3KIBy8kQj6rGwYSb73qVw+H1C27QtZT05jahaEMhf9kqwdhduqk/KpdRi/ghy8r1fhee5W8yrEZbEreQBG4BCCM4T6do6Xl53gU0JNOznx7smDfZsgtCpjbnf0wuiY5sqWgWoB7IDkQwq/V/ekBPZ2J97m43tBTP6J9pMYmU/pQJGN9jxNNtum8W84d9mZWm19Kar3i3KmDi7bJSAwZGXS9MKTPfl76jHVjsZ94iQEZBTNjoYUVc/E5y3/vVroq3NfE6dh4j0dfRZhfz6HJQtqy/dHNMu14chTvQFzN+HuFRUa0swEEsNjQqFmqRkB+sMDfw1mbjP3fb46pcnWdXHQyJP0q3vePLwanvwI7u32UlyaXe9bWlb6nuzBlqfwGzm7oT021yHUtRmK3Gr5/nUWwJzjvzEOn5hvnUUU37cw9WBb+itd+r9y469tBW2vZFyIodNSzgQ5/GCPbtfRjPKZ+Lfev3G0kjBRDKhcSFc3oakqcWdBC9C1KLKFYwZMRuE3wu7sQMk4PkTg5xnnUn8m9462DljfkieNAZzBwdIbPCGtu/dhQhaJcz/Dq0FgIkwoLXYzJvzgPuZq8MqHA/eJnssELvWRLoWLncyQz1giUgZvU4v+0xcMuMqQA+TsnIAEhNG8T8hsrVqD3dQvkbaWsgCCQY0EkjHeZUCAwEAAQ=="

private let sampleKeyData = Data(base64Encoded: keyBase64, options: [])!

class KeyUtilsTests : XCTestCase {
    override func setUp() {
        super.setUp()
    }
    override func tearDown() {
        super.tearDown()
    }
    
    func testCreateKeyFromData() throws {
        _ = try RSAKey(keyData: sampleKeyData)
    }
    
    func testAddBadKeyFormat() {
        do {
            _ = try RSAKey(keyData: Data("this_is_not_a_rsa_key".utf8))
            XCTFail("should fail")
        } catch RSAKey.Error.invalidKeyData(_) {}
        catch {
            XCTFail("should be a  KeyUtilError.BadKeyFormat  : \(error)")
        }
    }
    func testAddPublicPEMKey() throws {
        let pemData = try Data(contentsOf: testDataURL(name: "public", extension: "pem"))
        _ = try RSAKey(publicPEMKey: pemData)
    }
    func testModulusExponent() throws {
        let modulusData = try Data(contentsOf: testDataURL(name: "public_modulus", extension: "bin"))
        let exponentData = try Data(contentsOf: testDataURL(name: "public_exponent", extension: "bin"))
        _ = try RSAKey(modulus: modulusData, exponent: exponentData)
    }
}
