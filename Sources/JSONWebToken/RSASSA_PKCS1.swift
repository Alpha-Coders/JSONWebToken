//
//  RSASSA_PKCS1.swift
//  JSONWebToken
//
//  Created by Antoine Palazzolo on 18/11/15.
//

import Foundation
import Security

public struct RSAKey {
    enum Error : Swift.Error {
        case securityInvalidStatus(OSStatus)
        case invalidKeyData(CFError?)
        case publicKeyNotFoundInCertificate
        case cannotCreateCertificateFromData
        case invalidP12ImportResult
        case invalidP12NoIdentityFound
    }
    
    let value: SecKey
  
    public init(secKey: SecKey) {
        self.value = secKey
    }
    public init(secCertificate cert: SecCertificate) throws {
        try self.init(secKey: cert.publicKey())
    }
    //Creates a certificate object from a DER representation of a certificate.
    public init(certificateData data: Data) throws {
        if let cert = SecCertificateCreateWithData(nil, data as CFData) {
            try self.init(secCertificate : cert)
        } else {
            throw Error.cannotCreateCertificateFromData
        }
    }
    
    //PKCS #1 formatted key data
    public init(keyData: Data, isPublic: Bool = true) throws {
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: isPublic ? kSecAttrKeyClassPublic : kSecAttrKeyClassPrivate
        ]
        var error: Unmanaged<CFError>? = nil
        if let key = SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, &error) {
            self.init(secKey: key)
        } else {
            throw Error.invalidKeyData(error?.takeRetainedValue())
        }        
    }
    public init(modulus: Data, exponent: Data, isPublic: Bool = true) throws {
        let keyData = Data(modulus: modulus, exponent: exponent)
        try self.init(keyData: keyData, isPublic: isPublic)
    }
    public init(publicPEMKey data: Data) throws {
        let decodedKeyData = try PEMDataDecoder.decodePEMPublicKeyData(data)
        try self.init(keyData: decodedKeyData)
    }
    
    public static func keysFromPkcs12Identity(_ p12Data: Data, passphrase: String) throws -> (publicKey: RSAKey, privateKey: RSAKey) {
        var importResult : CFArray? = nil
        let importParam = [kSecImportExportPassphrase as String: passphrase]
        let status = SecPKCS12Import(p12Data as CFData, importParam as CFDictionary, &importResult)
        
        guard status == errSecSuccess else { throw Error.securityInvalidStatus(status) }
        
        let keys: (publicKey: SecKey, privateKey: SecKey)
        if let array = importResult.map({unsafeBitCast($0,to: NSArray.self)}),
            let content = array.firstObject as? NSDictionary,
            let identity = (content[kSecImportItemIdentity as String] as! SecIdentity?) {
            
            var privateKeyResult: SecKey? = nil
            var certificateResult: SecCertificate? = nil
            let status = (
                SecIdentityCopyPrivateKey(identity, &privateKeyResult),
                SecIdentityCopyCertificate(identity, &certificateResult)
            )
            guard status.0 == errSecSuccess else { throw Error.securityInvalidStatus(status.0) }
            guard status.1 == errSecSuccess else { throw Error.securityInvalidStatus(status.1) }
            if let privateKey = privateKeyResult, let publicKey = try certificateResult?.publicKey() {
                keys = (publicKey, privateKey)
            } else {
                throw Error.invalidP12ImportResult
            }
        } else {
            throw Error.invalidP12NoIdentityFound
        }
        return (RSAKey(secKey: keys.publicKey), RSAKey(secKey: keys.privateKey))
    }
    func verify(_ input: Data, signature: Data, hashFunction: SignatureAlgorithm.HashFunction) -> Bool {
        let signedDataHash = input.sha(hashFunction)
        
        let result = signature.withUnsafeBytes { (signatureBuffer: UnsafeRawBufferPointer) -> OSStatus in
            let signatureBuffer = signatureBuffer.bindMemory(to: UInt8.self)
            return signedDataHash.withUnsafeBytes { (signedHashBuffer: UnsafeRawBufferPointer) -> OSStatus in
                let signedHashBuffer = signedHashBuffer.bindMemory(to: UInt8.self)
                return SecKeyRawVerify(self.value, hashFunction.padding,
                                       signedHashBuffer.baseAddress!, signedHashBuffer.count,
                                       signatureBuffer.baseAddress!, signatureBuffer.count)
            }
        }
        
        switch result {
        case errSecSuccess:
            return true
        default:
            return false
        }
    }
    func sign(_ input: Data, hashFunction: SignatureAlgorithm.HashFunction) throws -> Data {
        let signedDataHash = input.sha(hashFunction)
        
        var result = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: SecKeyGetBlockSize(self.value))
        defer { result.deallocate() }
        var resultSize: Int = result.count
        
        let status = signedDataHash.withUnsafeBytes { signedDataHashBuffer -> OSStatus in
            let signedDataHashBuffer = signedDataHashBuffer.bindMemory(to: UInt8.self)
            return SecKeyRawSign(self.value, hashFunction.padding,
                                 signedDataHashBuffer.baseAddress!, signedDataHashBuffer.count,
                                 result.baseAddress!, &resultSize)
        }
        switch status {
        case errSecSuccess:
            return Data(result[0..<resultSize])
        default:
            throw RSAKey.Error.securityInvalidStatus(status)
        }
    }
}
fileprivate extension SecCertificate {
    func publicKey() throws -> SecKey {
        if #available(iOS 12.0, *) {
            if let publicKey = SecCertificateCopyKey(self) {
                return publicKey
            } else {
                throw RSAKey.Error.publicKeyNotFoundInCertificate
            }
        } else {
            var trust: SecTrust? = nil
            let result = SecTrustCreateWithCertificates(self, nil, &trust)
            if result == errSecSuccess && trust != nil {
                if let publicKey = SecTrustCopyPublicKey(trust!) {
                    return publicKey
                } else {
                    throw RSAKey.Error.publicKeyNotFoundInCertificate
                }
            } else {
                throw RSAKey.Error.securityInvalidStatus(result)
            }
        }
    }
}

fileprivate extension SignatureAlgorithm.HashFunction {
    var padding: SecPadding {
        switch self {
        case .sha256:
            return SecPadding.PKCS1SHA256
        case .sha384:
            return SecPadding.PKCS1SHA384
        case .sha512:
            return SecPadding.PKCS1SHA512
        }
    }
}

public struct RSAPKCS1Verifier: SignatureValidator {
    let hashFunction: SignatureAlgorithm.HashFunction
    let key: RSAKey
    
    public init(key: RSAKey, hashFunction: SignatureAlgorithm.HashFunction) {
        self.hashFunction = hashFunction
        self.key = key
    }
    public func canVerifyWithSignatureAlgorithm(_ alg: SignatureAlgorithm) -> Bool {
        if case SignatureAlgorithm.rsassa_PKCS1(self.hashFunction) = alg {
            return true
        }
        return false
    }
    public func verify(_ input: Data, signature: Data) -> Bool {
        return self.key.verify(input, signature: signature, hashFunction: self.hashFunction)
    }
}

public struct RSAPKCS1Signer: TokenSigner {
    let hashFunction: SignatureAlgorithm.HashFunction
    let key: RSAKey
    
    public init(hashFunction : SignatureAlgorithm.HashFunction, key : RSAKey) {
        self.hashFunction = hashFunction
        self.key = key
    }
    
    public var signatureAlgorithm : SignatureAlgorithm {
        return .rsassa_PKCS1(self.hashFunction)
    }

    public func sign(_ input: Data) throws -> Data {
        return try self.key.sign(input, hashFunction: self.hashFunction)
    }
}
