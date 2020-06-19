//
//  SecKeyUtils_deprecated.swift
//  JSONWebToken
//
//  Created by Antoine Palazzolo on 20/05/2020.
//

import Foundation

//these methods use a keychain api side effect to create public key from raw data
public extension RSAKey {
    
    @available(*, deprecated, message: "use init(keyData:)")
    @discardableResult static func registerOrUpdateKey(_ keyData: Data, tag: String) throws -> RSAKey {
        let key : SecKey? = try {
            if let existingData = try getKeyData(tag) {
                let newData = keyData.dataByStrippingX509Header()
                if existingData != newData {
                    try updateKey(tag, data: newData)
                }
                return try getKey(tag)
            } else {
                return try addKey(tag, data: keyData.dataByStrippingX509Header())
            }
        }()
        if let result = key {
            return RSAKey(secKey : result)
        } else {
            throw RSAKey.Error.invalidKeyData(nil)
        }
    }
    @available(*, deprecated, message: "use init(modulus:, exponent:)")
    @discardableResult static func registerOrUpdateKey(modulus: Data, exponent: Data, tag: String) throws -> RSAKey {
        let combinedData = Data(modulus: modulus, exponent: exponent)
        return try RSAKey.registerOrUpdateKey(combinedData, tag : tag)
    }
    @available(*, deprecated, message: "use init(publicPEMKey:)")
    @discardableResult static func registerOrUpdatePublicPEMKey(_ pemData: Data, tag: String) throws -> RSAKey {
        let keyData = try PEMDataDecoder.decodePEMPublicKeyData(pemData)
        return try RSAKey.registerOrUpdateKey(keyData, tag: tag)
    }
    @available(*, deprecated)
    static func registeredKeyWithTag(_ tag: String) -> RSAKey? {
        return ((((try? getKey(tag)) as SecKey??)) ?? nil).map(RSAKey.init)
    }
    @available(*, deprecated)
    static func removeKeyWithTag(_ tag: String) {
        do {
            try deleteKey(tag)
        } catch {}
    }
}
private extension Data {
    func dataByStrippingX509Header() -> Data {
        
        var bytes = [CUnsignedChar](repeating: 0, count: self.count)
        (self as NSData).getBytes(&bytes, length:self.count)
        
        var range = NSRange(location: 0, length: self.count)
        var offset = 0
        
        // ASN.1 Sequence
        if bytes[offset] == 0x30 {
            offset += 1
            
            // Skip over length
            let _ = NSInteger(octetBytes: bytes, startIdx: &offset)
            
            let OID: [CUnsignedChar] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                                        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]
            let slice: [CUnsignedChar] = Array(bytes[offset..<(offset + OID.count)])
            
            if slice == OID {
                offset += OID.count
                
                // Type
                if bytes[offset] != 0x03 {
                    return self
                }
                
                offset += 1
                
                // Skip over the contents length field
                let _ = NSInteger(octetBytes: bytes, startIdx: &offset)
                
                // Contents should be separated by a null from the header
                if bytes[offset] != 0x00 {
                    return self
                }
                
                offset += 1
                range.location += offset
                range.length -= offset
            } else {
                return self
            }
        }
        
        return self.subdata(in : Range(range)!)
    }
}
private extension NSInteger {
    init?(octetBytes: [CUnsignedChar], startIdx: inout NSInteger) {
        if octetBytes[startIdx] < 128 {
            // Short form
            self.init(octetBytes[startIdx])
            startIdx += 1
        } else {
            // Long form
            let octets = NSInteger(octetBytes[startIdx] - CUnsignedChar(128))
            
            if octets > octetBytes.count - startIdx {
                self.init(0)
                return nil
            }
            
            var result = UInt64(0)
            
            for j in 1...octets {
                result = (result << 8)
                result = result + UInt64(octetBytes[startIdx + j])
            }
            
            startIdx += 1 + octets
            self.init(result)
        }
    }
}
private func getKey(_ tag: String) throws -> SecKey? {
    var keyRef: AnyObject?
    
    var query = matchQueryWithTag(tag)
    query[kSecReturnRef as String] = kCFBooleanTrue
    
    let status = SecItemCopyMatching(query as CFDictionary, &keyRef)
    
    switch status {
    case errSecSuccess:
        if keyRef != nil {
            return (keyRef as! SecKey)
        } else {
            return nil
        }
    case errSecItemNotFound:
        return nil
    default:
        throw RSAKey.Error.securityInvalidStatus(status)
    }
}
private func getKeyData(_ tag: String) throws -> Data? {
    
    var query = matchQueryWithTag(tag)
    query[kSecReturnData as String] = kCFBooleanTrue
    
    var result: AnyObject? = nil
    let status = SecItemCopyMatching(query as CFDictionary, &result)

    switch status {
    case errSecSuccess:
        return (result as! Data)
    case errSecItemNotFound:
        return nil
    default:
        throw RSAKey.Error.securityInvalidStatus(status)
    }
}
private func updateKey(_ tag: String, data: Data) throws {
    let query = matchQueryWithTag(tag)
    let updateParam = [kSecValueData as String : data]
    let status = SecItemUpdate(query as CFDictionary, updateParam as CFDictionary)
    guard status == errSecSuccess else {
        throw RSAKey.Error.securityInvalidStatus(status)
    }
}

private func deleteKey(_ tag: String) throws {
    let query = matchQueryWithTag(tag)
    let status = SecItemDelete(query as CFDictionary)
    if status != errSecSuccess {
        throw RSAKey.Error.securityInvalidStatus(status)
    }
}
private func matchQueryWithTag(_ tag : String) -> Dictionary<String, Any> {
    return [
        kSecAttrKeyType as String : kSecAttrKeyTypeRSA,
        kSecClass as String : kSecClassKey,
        kSecAttrApplicationTag as String : tag,
    ]
}

private func addKey(_ tag: String, data: Data) throws -> SecKey? {
    var publicAttributes = Dictionary<String, Any>()
    publicAttributes[kSecAttrKeyType as String] = kSecAttrKeyTypeRSA
    publicAttributes[kSecClass as String] = kSecClassKey
    publicAttributes[kSecAttrApplicationTag as String] = tag as CFString
    publicAttributes[kSecValueData as String] = data as CFData
    publicAttributes[kSecReturnPersistentRef as String] = kCFBooleanTrue
    
    var persistentRef: CFTypeRef?
    let status = SecItemAdd(publicAttributes as CFDictionary, &persistentRef)
    if status == noErr || status == errSecDuplicateItem {
        return try getKey(tag)
    }
    throw RSAKey.Error.securityInvalidStatus(status)
}
