local expect = require "cc.expect"
local chain = require "cert.chain"
local container = require "cert.container"
local crypto = require "cert.crypto"
local csr = require "cert.csr"
local signature = require "cert.signature"
local util = require "cert.util"
local random = require "ccryptolib.random"

local libcert = {
    chain = chain,
    container = container,
    crypto = crypto,
    csr = csr,
    signature = signature
}

--- Generates an Ed25519 and PKCS#8 private key for signing, optionally encrypted with a password.
---@param password? string A password to encrypt the key with
---@return string key The generated private key
---@return string pk8 The PEM-encoded PKCS#8 key container for the key
function libcert.generatePrivateKeyForSigning(password)
    expect(1, password, "string", "nil")
    local key = random.random(32)
    ---@type PKCS8
    local pk8 = {
        version = 1,
        privateKeyAlgorithm = {type = container.signatureAlgorithmOIDs.ED25519},
        privateKey = key
    }
    if password then
        return key, container.encodePEM(container.savePKCS8Encrypted(crypto.encryptKey(pk8, password)), "ENCRYPTED PRIVATE KEY")
    else return key, container.encodePEM(container.savePKCS8(pk8), "PRIVATE KEY") end
end

--- Generates an X25519 and PKCS#8 private key for encryption, optionally encrypted with a password.
---@param password? string A password to encrypt the key with
---@return string key The generated private key
---@return string pk8 The PEM-encoded PKCS#8 key container for the key
function libcert.generatePrivateKeyForEncryption(password)
    expect(1, password, "string", "nil")
    local key = random.random(32)
    ---@type PKCS8
    local pk8 = {
        version = 1,
        privateKeyAlgorithm = {type = container.publicKeyAlgorithmOIDs.X25519},
        privateKey = key
    }
    if password then
        return key, container.encodePEM(container.savePKCS8Encrypted(crypto.encryptKey(pk8, password)), "ENCRYPTED PRIVATE KEY")
    else return key, container.encodePEM(container.savePKCS8(pk8), "PRIVATE KEY") end
end

local stringNameValues = {
    [container.nameOIDs.uniqueIdentifier] = true,
    [container.nameOIDs.dnQualifier] = true,
    [container.nameOIDs.serialNumber] = true,
    [container.nameOIDs.countryName] = true
}

--- Generates a certificate signing request for a private key.
---@param pk8 string The PEM-encoded PKCS#8 key container to generate for
---@param name {[string]: string} The subject of the certificate request, as a key-value map of container.nameOIDs to strings
---@param password? string The password protecting the private key, if required
---@return string pk10 The PEM-encoded PKCS#10 CSR container
function libcert.generateCSR(pk8, name, password)
    expect(1, pk8, "string")
    expect(2, name, "table")
    expect(3, password, "string", "nil")
    local der, typ = container.decodePEM(pk8)
    if typ == "ENCRYPTED PRIVATE KEY" then
        if not password then error("Private key is encrypted, but no password was provided", 2) end
        pk8 = crypto.decryptKey(container.loadPKCS8Encrypted(der), password)
    else pk8 = container.loadPKCS8(der) end
    ---@type Name
    local subject = {rdnSequence = {}}
    for k, v in pairs(name) do
        if not stringNameValues[k] then v = {uTF8String = v} end
        subject.rdnSequence[#subject.rdnSequence+1] = {
            {
                type = k,
                value = v
            }
        }
    end
    return container.encodePEM(container.savePKCS10(csr.generate(pk8, subject)), "CERTIFICATE REQUEST")
end

--- Signs a certificate signature request, creating a new certificate.
---@param pk10 string The PEM-encoded PKCS#10 CSR to sign
---@param cert string The PEM-encoded X.509 certificate of the issuer
---@param pk8 string The PEM-encoded PKCS#8 private key of the issuer
---@param serialNumber number|string The serial number for the new certificate
---@param days number The number of days the certificate is valid for
---@param password? string The password protecting the private key, if required
---@return string outcert The new PEM-encoded X.509 certificate for the request
function libcert.signCSR(pk10, cert, pk8, serialNumber, days, password)
    expect(1, pk10, "string")
    expect(2, cert, "string")
    expect(3, pk8, "string")
    expect(4, serialNumber, "number", "string")
    expect(5, days, "number")
    expect(6, password, "string", "nil")
    local der, typ = container.decodePEM(pk8)
    if typ == "ENCRYPTED PRIVATE KEY" then
        if not password then error("Private key is encrypted, but no password was provided", 2) end
        pk8 = crypto.decryptKey(container.loadPKCS8Encrypted(der), password)
    else pk8 = container.loadPKCS8(der) end
    if type(serialNumber) == "string" then serialNumber = {type = "INTEGER", data = serialNumber} end
    return container.encodePEM(
        container.saveX509(
            csr.sign(
                container.loadPKCS10(container.decodePEM(pk10)),
                container.loadX509(container.decodePEM(cert)),
                pk8,
                serialNumber,
                days
            )
        ), "CERTIFICATE"
    )
end

--- Self-signs a certificate signature request, creating a new certificate.
---@param pk10 string The PEM-encoded PKCS#10 CSR to sign
---@param pk8 string The PEM-encoded PKCS#8 private key of the requester
---@param serialNumber number|string The serial number for the new certificate
---@param days number The number of days the certificate is valid for
---@param password? string The password protecting the private key, if required
---@return string outcert The new PEM-encoded X.509 certificate for the request
function libcert.selfSignCSR(pk10, pk8, serialNumber, days, password)
    expect(1, pk10, "string")
    expect(2, pk8, "string")
    expect(3, serialNumber, "number", "string")
    expect(4, days, "number")
    expect(5, password, "string", "nil")
    local der, typ = container.decodePEM(pk8)
    if typ == "ENCRYPTED PRIVATE KEY" then
        if not password then error("Private key is encrypted, but no password was provided", 2) end
        pk8 = crypto.decryptKey(container.loadPKCS8Encrypted(der), password)
    else pk8 = container.loadPKCS8(der) end
    if type(serialNumber) == "string" then serialNumber = {type = "INTEGER", data = serialNumber} end
    return container.encodePEM(
        container.saveX509(
            csr.selfSign(
                container.loadPKCS10(container.decodePEM(pk10)),
                pk8,
                serialNumber,
                days
            )
        ), "CERTIFICATE"
    )
end

--- Encrypts a block of data with a password.
---@param data string The data to encrypt
---@param password string The password to encrypt with
---@return string pk7 A PEM-encoded PKCS#7/CMS container with the encrypted data
function libcert.encrypt(data, password)
    expect(1, data, "string")
    expect(2, password, "string")
    return container.encodePEM(container.savePKCS7(crypto.encrypt(data, crypto.passwordKey(password))), "CMS")
end

--- Decrypts PEM-encoded PKCS#7 encrypted data with a password.
---@param data string The PEM-encoded PKCS#7 container to decrypt
---@param password string The password to decrypt with
---@return string data The decrypted data
function libcert.decrypt(data, password)
    expect(1, data, "string")
    expect(2, password, "string")
    return crypto.decrypt(container.loadPKCS7(container.decodePEM(data)), crypto.passwordKey(password))
end

--- Encrypts a block of data with a sender's private key + certificate and receiver's certificate.
---@param data string The data to encrypt
---@param myKey string The PEM-encoded PKCS#8 private key of the sender
---@param myCert string The PEM-encoded X.509 certificate of the sender
---@param theirCert string The PEM-encoded X.509 certificate of the receiver
---@param password? string The password protecting the private key, if required
---@return string pk7 A PEM-encoded PKCS#7/CMS container with the encrypted data
function libcert.encryptExchange(data, myKey, myCert, theirCert, password)
    expect(1, data, "string")
    expect(2, myKey, "string")
    expect(3, myCert, "string")
    expect(4, theirCert, "string")
    expect(5, password, "string", "nil")
    local pk8, typ = container.decodePEM(myKey)
    if typ == "ENCRYPTED PRIVATE KEY" then
        if not password then error("Private key is encrypted, but no password was provided", 2) end
        pk8 = crypto.decryptKey(container.loadPKCS8Encrypted(pk8), password)
    else pk8 = container.loadPKCS8(pk8) end
    return container.encodePEM(container.savePKCS7(crypto.encrypt(data, crypto.exchangedKey(pk8, container.loadX509(container.decodePEM(myCert)), container.loadX509(container.decodePEM(theirCert))))), "CMS")
end

--- Decrypts PEM-encoded PKCS#7 encrypted data with a receiver's private key and a sender's certificate.
---@param data string The PEM-encoded PKCS#7 container to decrypt
---@param myKey string The PEM-encoded PKCS#8 private key of the receiver
---@param myCert string The PEM-encoded X.509 certificate of the receiver
---@param theirCert string The PEM-encoded X.509 certificate of the sender
---@param password? string The password protecting the private key, if required
---@return string data The decrypted data
function libcert.decryptExchange(data, myKey, myCert, theirCert, password)
    expect(1, data, "string")
    expect(2, myKey, "string")
    expect(3, myCert, "string")
    expect(4, theirCert, "string")
    expect(5, password, "string", "nil")
    local pk8, typ = container.decodePEM(myKey)
    if typ == "ENCRYPTED PRIVATE KEY" then
        if not password then error("Private key is encrypted, but no password was provided", 2) end
        pk8 = crypto.decryptKey(container.loadPKCS8Encrypted(pk8), password)
    else pk8 = container.loadPKCS8(pk8) end
    return crypto.decrypt(container.loadPKCS7(container.decodePEM(data)), crypto.exchangedKey(pk8, container.loadX509(container.decodePEM(theirCert)), container.loadX509(container.decodePEM(myCert))))
end

--- Creates a PEM-encoded PKCS#7 signature for the specified data, using the keys provided.
---@param cert X509|string The PEM-encoded certificate to sign with
---@param key PKCS8|string The PEM-encoded private key for the certificate
---@param data string The data to sign
---@param additionalCerts? string[] Any additional certificates needed to verify the signature (e.g. CA certificates)
---@param password? string The password for the key, if required
---@return string sig The generated signature, PEM-encoded
function libcert.sign(cert, key, data, additionalCerts, password)
    expect(1, cert, "string", "table")
    expect(2, key, "string", "table")
    expect(3, data, "string")
    expect(4, additionalCerts, "table", "nil")
    expect(5, password, "string", "nil")
    if additionalCerts then
        for i, v in ipairs(additionalCerts) do additionalCerts[i] = container.loadX509(container.decodePEM(v)) end
    end
    if type(cert) == "string" then cert = container.loadX509(container.decodePEM(cert)) end
    if type(key) == "string" then
        local pk8, typ = container.decodePEM(key)
        if typ == "ENCRYPTED PRIVATE KEY" then
            if not password then error("Private key is encrypted, but no password was provided", 2) end
            pk8 = crypto.decryptKey(container.loadPKCS8Encrypted(pk8), password)
        else pk8 = container.loadPKCS8(pk8) end
        key = pk8
    end
    return container.encodePEM(container.savePKCS7(signature.sign(cert, key, data, additionalCerts)), "PKCS7")
end

--- Verifies the signature of data using a PEM-encoded PKCS#7 signature.
---@param sig string|PKCS7SignedData The PEM-encoded PKCS#7 signature of the original data
---@param data string The data to check
---@param validateCertificate? boolean Whether to validate the certificate's root of trust (defaults to true)
---@param rootPath? string The path to the root certificate store
---@param additionalRoots? (string|X509)[] Any additional root certificates to trust
---@return boolean valid Whether the signature is valid
---@return string|nil reason If not valid, a reason why it's invalid
function libcert.verify(sig, data, validateCertificate, rootPath, additionalRoots)
    if validateCertificate == nil then validateCertificate = true end
    expect(1, sig, "string", "table")
    expect(2, data, "string")
    expect(3, validateCertificate, "boolean")
    expect(4, rootPath, "string", "nil")
    expect(5, additionalRoots, "table", "nil")
    if type(sig) == "string" then sig = container.loadPKCS7(container.decodePEM(sig)) end
    local ok, err = signature.verify(sig, data)
    if not ok then return false, err end
    if validateCertificate then
        if additionalRoots then for i, v in ipairs(additionalRoots) do if type(v) == "string" then additionalRoots[i] = container.loadX509(container.decodePEM(v)) end end end
        return chain.validate(signature.getCertificate(sig, 1), sig.content.certificates, rootPath, additionalRoots)
    end
    return true
end

--- Validates a certificate up to a root of trust.
---@param cert string|X509 The certificate to start at
---@param certList? (string|X509)[] Additional certificates that may be in the chain of trust
---@param rootPath? string The path to the root certificate store (defaults to "/etc/certs")
---@param additionalRoots? (string|X509)[] Additional root certificates to trust
---@return boolean trusted Whether the certificate can be trusted
---@return string|nil reason If not trusted, a reason why the certificate failed to validate
function libcert.validate(cert, certList, rootPath, additionalRoots)
    expect(1, cert, "string", "table")
    expect(2, certList, "table", "nil")
    expect(3, rootPath, "string", "nil")
    expect(4, additionalRoots, "string", "nil")
    if type(cert) == "string" then cert = container.loadX509(container.decodePEM(cert)) end
    if certList then for i, v in ipairs(certList) do if type(v) == "string" then certList[i] = container.loadX509(container.decodePEM(v)) end end end
    if additionalRoots then for i, v in ipairs(additionalRoots) do if type(v) == "string" then additionalRoots[i] = container.loadX509(container.decodePEM(v)) end end end
    return chain.validate(cert, certList, rootPath, additionalRoots)
end

--- Prints a PEM-encoded object to the screen for debugging.
---@param data string The PEM object to display
function libcert.print(data)
    local der, typ = container.decodePEM(data)
    local obj
    if typ == "CERTIFICATE" then obj = container.loadX509(der)
    elseif typ == "PKCS#7" or typ == "CMS" then obj = container.loadPKCS7(der)
    elseif typ == "PRIVATE KEY" then obj = container.loadPKCS8(der)
    elseif typ == "ENCRYPTED PRIVATE KEY" then obj = container.loadPKCS8Encrypted(der)
    elseif typ == "CERTIFICATE REQUEST" then obj = container.loadPKCS10(der)
    else error("Unknown PEM data type", 2) end
    return container.print(obj)
end

return libcert
