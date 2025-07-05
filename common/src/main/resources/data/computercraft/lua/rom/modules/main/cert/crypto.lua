local container = require "cert.container"
local util = require "cert.util"
local chacha20 = require "ccryptolib.chacha20"
local poly1305 = require "ccryptolib.poly1305"
local random = require "ccryptolib.random"
local x25519 = require "ccryptolib.x25519"
local aes = require "aes"
local sha2 = require "sha2"

local crypto = {}

---@alias KeyEncryptor {encrypt: (fun(key: string): RecipientInfo), decrypt: (fun(enc: RecipientInfo): string|nil)}

--- Creates an exchanged key encryptor using an originator certificate and recipient certificate, plus local key.
---@param pk8 PKCS8 The local private key for the originator or receiver
---@param origCert X509 The certificate of the originator
---@param recvCert X509 The certificate of the receiver
---@return KeyEncryptor encryptor The created key encryptor
function crypto.exchangedKey(pk8, origCert, recvCert)
    local skt = pk8.privateKeyAlgorithm.type.string or pk8.privateKeyAlgorithm.type
    local sct = origCert.toBeSigned.subjectPublicKeyInfo.algorithm.type.string or origCert.toBeSigned.subjectPublicKeyInfo.algorithm.type
    local pct = recvCert.toBeSigned.subjectPublicKeyInfo.algorithm.type.string or recvCert.toBeSigned.subjectPublicKeyInfo.algorithm.type
    assert(skt == container.publicKeyAlgorithmOIDs.ED25519 or skt == container.publicKeyAlgorithmOIDs.X25519, "Unsupported originator private key type")
    assert(sct == container.publicKeyAlgorithmOIDs.X25519, "Unsupported originator public key type")
    assert(pct == container.publicKeyAlgorithmOIDs.X25519, "Unsupported receiver public key type")
    return {
        encrypt = function(key)
            local iv = random.random(16)
            local exchKey = x25519.exchange(pk8.privateKey, recvCert.toBeSigned.subjectPublicKeyInfo.subjectPublicKey.data)
            ---@type RecipientInfo
            local ri = {
                kari = {
                    version = 3,
                    originator = {
                        issuerAndSerialNumber = {
                            issuer = origCert.toBeSigned.issuer,
                            serialNumber = origCert.toBeSigned.serialNumber
                        }
                    },
                    keyEncryptionAlgorithm = {
                        type = container.encryptionAlgorithmOIDs.AES256_CBC,
                        iv = iv
                    },
                    recipientEncryptedKeys = {
                        {
                            encryptedKey = aes.TableToString(aes.EncryptCBC(util.pkcs7pad(aes.StringToTable(key), 16), aes.StringToTable(exchKey), aes.StringToTable(iv))),
                            rid = {
                                issuerAndSerialNumber = {
                                    issuer = recvCert.toBeSigned.issuer,
                                    serialNumber = recvCert.toBeSigned.serialNumber
                                }
                            }
                        }
                    }
                }
            }
            return ri
        end,
        ---@param enc RecipientInfo
        decrypt = function(enc)
            if not enc.kari or enc.kari.version ~= 3 then return nil end
            if not enc.kari.originator.issuerAndSerialNumber then return nil end
            if not util.compareNames(enc.kari.originator.issuerAndSerialNumber.issuer, origCert.toBeSigned.issuer) then return nil end
            if enc.kari.originator.issuerAndSerialNumber.serialNumber ~= origCert.toBeSigned.serialNumber then return nil end
            local kt = enc.kari.keyEncryptionAlgorithm.type.string or enc.kari.keyEncryptionAlgorithm.type
            if kt ~= container.encryptionAlgorithmOIDs.AES128_CBC and kt ~= container.encryptionAlgorithmOIDs.AES192_CBC and kt ~= container.encryptionAlgorithmOIDs.AES256_CBC then return nil end
            for _, v in ipairs(enc.kari.recipientEncryptedKeys) do
                if v.rid.issuerAndSerialNumber and
                    util.compareNames(v.rid.issuerAndSerialNumber.issuer, recvCert.toBeSigned.issuer) and
                    v.rid.issuerAndSerialNumber.serialNumber == recvCert.toBeSigned.serialNumber then
                    local exchKey = x25519.exchange(pk8.privateKey, origCert.toBeSigned.subjectPublicKeyInfo.subjectPublicKey.data)
                    local ok, res = pcall(aes.DecryptCBC, aes.StringToTable(v.encryptedKey), aes.StringToTable(exchKey), aes.StringToTable(enc.kari.keyEncryptionAlgorithm.iv))
                    if ok and res and res[#res] > 0 and res[#res] < 17 then return aes.TableToString(util.pkcs7unpad(res)) end
                end
            end
            return nil
        end
    }
end

--- Creates a key encryptor from a pre-shared key.
---@param psk string The pre-shared key to encrypt with
---@param id string An ID for the key
---@return KeyEncryptor encryptor The created key encryptor
function crypto.sharedKey(psk, id)
    local pkt
    if #psk == 16 then pkt = container.encryptionAlgorithmOIDs.AES128_CBC
    elseif #psk == 24 then pkt = container.encryptionAlgorithmOIDs.AES192_CBC
    elseif #psk == 32 then pkt = container.encryptionAlgorithmOIDs.AES256_CBC
    else error("Invalid key length", 2) end
    return {
        encrypt = function(key)
            local iv = random.random(16)
            ---@type RecipientInfo
            local ri = {
                kekri = {
                    version = 4,
                    kekid = {
                        subjectKeyIdentifier = id
                    },
                    keyEncryptionAlgorithm = {
                        type = pkt,
                        iv = iv
                    },
                    encryptedKey = aes.TableToString(aes.EncryptCBC(util.pkcs7pad(aes.StringToTable(key), 16), aes.StringToTable(psk), aes.StringToTable(iv)))
                }
            }
            return ri
        end,
        ---@param enc RecipientInfo
        decrypt = function(enc)
            if not enc.kekri or enc.kekri.version ~= 4 then return nil end
            if enc.kekri.kekid.subjectKeyIdentifier ~= id then return nil end
            local kt = enc.kekri.keyEncryptionAlgorithm.type.string or enc.kekri.keyEncryptionAlgorithm.type
            if kt ~= pkt then return nil end
            local ok, res = pcall(aes.DecryptCBC, aes.StringToTable(enc.kekri.encryptedKey), aes.StringToTable(psk), aes.StringToTable(enc.kekri.keyEncryptionAlgorithm.iv))
            if ok and res and res[#res] > 0 and res[#res] < 17 then return aes.TableToString(util.pkcs7unpad(res)) end
            return nil
        end
    }
end

--- Creates a key encryptor from a password.
---@param password string The password to encrypt with
---@return KeyEncryptor encryptor The created key encryptor
function crypto.passwordKey(password, hasher, iter)
    hasher = hasher or sha2.sha256
    local prf, hl
    if hasher == sha2.sha1 then
        prf = container.pseudoRandomFunctionOIDs.HMAC_SHA1
        hl = 20
    elseif hasher == sha2.sha224 then
        prf = container.pseudoRandomFunctionOIDs.HMAC_SHA224
        hl = 28
    elseif hasher == sha2.sha256 then
        prf = container.pseudoRandomFunctionOIDs.HMAC_SHA256
        hl = 32
    elseif hasher == sha2.sha384 then
        prf = container.pseudoRandomFunctionOIDs.HMAC_SHA384
        hl = 48
    elseif hasher == sha2.sha512 then
        prf = container.pseudoRandomFunctionOIDs.HMAC_SHA512
        hl = 64
    elseif hasher == sha2.sha512_224 then
        prf = container.pseudoRandomFunctionOIDs.HMAC_SHA512_224
        hl = 28
    elseif hasher == sha2.sha512_256 then
        prf = container.pseudoRandomFunctionOIDs.HMAC_SHA512_256
        hl = 32
    else error("Unknown hashing algorithm", 2) end
    return {
        encrypt = function(key)
            ---@type RecipientInfo
            local ri = {
                pwri = {
                    version = 0,
                    keyDerivationAlgorithm = {
                        type = container.keyDerivationAlgorithmOIDs.PBKDF2,
                        pbkdf2Parameters = {
                            iterationCount = iter or 4096,
                            salt = {
                                specified = random.random(16)
                            },
                            keyLength = 32,
                            prf = {type = prf}
                        }
                    },
                    keyEncryptionAlgorithm = {
                        type = container.encryptionAlgorithmOIDs.AES256_CBC,
                        iv = random.random(16)
                    },
                    encryptedKey = ""
                }
            }
            local pk = util.pbkdf2(function(d, k) return {sha2.hmac(hasher, k, string.char(table.unpack(d))):byte(1, -1)} end, hl, password, ri.pwri.keyDerivationAlgorithm.pbkdf2Parameters.salt.specified, iter or 4096, 32)
            ri.pwri.encryptedKey = aes.TableToString(aes.EncryptCBC(util.pkcs7pad(aes.StringToTable(key), 16), aes.StringToTable(pk), aes.StringToTable(ri.pwri.keyEncryptionAlgorithm.iv)))
            return ri
        end,
        ---@param enc RecipientInfo
        decrypt = function(enc)
            if not enc.pwri or enc.pwri.version ~= 0 then return nil end
            if not enc.pwri.keyDerivationAlgorithm or (enc.pwri.keyDerivationAlgorithm.type.string or enc.pwri.keyDerivationAlgorithm.type) ~= container.keyDerivationAlgorithmOIDs.PBKDF2 then return nil end
            if not enc.pwri.keyDerivationAlgorithm.pbkdf2Parameters.prf then return nil end
            local prft = enc.pwri.keyDerivationAlgorithm.pbkdf2Parameters.prf.type.string or enc.pwri.keyDerivationAlgorithm.pbkdf2Parameters.prf.type
            if prft ~= prf then return nil end
            local kt = enc.pwri.keyEncryptionAlgorithm.type.string or enc.pwri.keyEncryptionAlgorithm.type
            local kl
            if kt == container.encryptionAlgorithmOIDs.AES128_CBC then kl = 16
            elseif kt == container.encryptionAlgorithmOIDs.AES192_CBC then kl = 24
            elseif kt == container.encryptionAlgorithmOIDs.AES256_CBC then kl = 32
            else return nil end
            local pk = util.pbkdf2(function(d, k) return {sha2.hmac(hasher, k, string.char(table.unpack(d))):byte(1, -1)} end, hl, password, enc.pwri.keyDerivationAlgorithm.pbkdf2Parameters.salt.specified, enc.pwri.keyDerivationAlgorithm.pbkdf2Parameters.iterationCount, kl)
            local ok, res = pcall(aes.DecryptCBC, aes.StringToTable(enc.pwri.encryptedKey), aes.StringToTable(pk), aes.StringToTable(enc.pwri.keyEncryptionAlgorithm.iv))
            if ok and res and res[#res] > 0 and res[#res] < 17 then return aes.TableToString(util.pkcs7unpad(res)) end
            return nil
        end
    }
end

--- Encrypts a string of data into a PKCS#7 container.
---@param data string|PKCS7 The data to encrypt
---@param ... KeyEncryptor The key encryptor(s) to encrypt with
---@return PKCS7 pk7 The generated PKCS#7 container
function crypto.encrypt(data, ...)
    local ctype = container.pkcs7ContentTypeOIDs.data
    if type(data) == "table" then
        ctype = data.type.string or data.type
        data = container.savePKCS7(data)
    end
    local key = random.random(32)
    local nonce = random.random(12)
    ---@type PKCS7AuthenticatedEncryptedData
    local pk7 = {
        type = container.pkcs7ContentTypeOIDs.authEnvelopedData,
        content = {
            version = 0,
            recipientInfos = {},
            authEncryptedContentInfo = {
                contentEncryptionAlgorithm = {
                    type = container.encryptionAlgorithmOIDs.ChaCha20_Poly1305,
                    nonce = nonce
                },
                contentType = ctype,
                encryptedContent = chacha20.crypt(key, nonce, data)
            },
            mac = poly1305.mac(key, data)
        }
    }
    for i, v in ipairs{...} do
        pk7.content.recipientInfos[i] = v.encrypt(key)
        if not pk7.content.recipientInfos[i].pwri then pk7.content.version = 2 end
    end
    return pk7
end

--- Decrypts a PKCS#7 container using the specified key.
---@param pk7 PKCS7 The container to decrypt
---@param ... KeyEncryptor The key encryptor(s) to decrypt with
---@return string|PKCS7 data The decrypted data
function crypto.decrypt(pk7, ...)
    if (pk7.type.string or pk7.type) ~= container.pkcs7ContentTypeOIDs.authEnvelopedData then error("Not an authenticated data object", 2) end
    if (pk7.content.authEncryptedContentInfo.contentEncryptionAlgorithm.type.string or pk7.content.authEncryptedContentInfo.contentEncryptionAlgorithm.type) ~= container.encryptionAlgorithmOIDs.ChaCha20_Poly1305 then error("Unsupported algorithm", 2) end
    local key
    for _, enc in ipairs{...} do
        for _, ri in ipairs(pk7.content.recipientInfos) do
            key = enc.decrypt(ri)
            if key then break end
        end
        if key then break end
    end
    if not key then error("Could not find valid key encryptor", 2) end
    local data = chacha20.crypt(key, pk7.content.authEncryptedContentInfo.contentEncryptionAlgorithm.nonce, pk7.content.authEncryptedContentInfo.encryptedContent)
    if poly1305.mac(key, data) ~= pk7.content.mac then error("Could not authenticate data", 2) end
    if (pk7.content.authEncryptedContentInfo.contentType.string or pk7.content.authEncryptedContentInfo.contentType) == container.pkcs7ContentTypeOIDs.data then return data end
    return container.loadPKCS7(data)
end

--- Encrypts a PKCS#8 key container with a password.
---@param pk8 PKCS8 The key to encrypt
---@param password string The password to encrypt with
---@param hasher? fun(data: string): string The hasher function to use (must be one of sha2.sha*, defaults to sha2.sha256)
---@param iter? number The number of iterations to use when generating the key
---@return EncryptedPrivateKeyInfo pk8e The encrypted PKCS#8 container
function crypto.encryptKey(pk8, password, hasher, iter)
    hasher = hasher or sha2.sha256
    local data = container.savePKCS8(pk8)
    ---@type EncryptedPrivateKeyInfo
    local pk8e = {
        encryptionAlgorithm = {
            type = container.passwordBasedEncryptionSchemeOIDs.PBES2,
            pbes2Parameters = {
                encryptionScheme = {
                    type = container.encryptionAlgorithmOIDs.AES256_CBC,
                    iv = random.random(16)
                },
                keyDerivationFunc = {
                    type = container.keyDerivationAlgorithmOIDs.PBKDF2,
                    pbkdf2Parameters = {
                        salt = {
                            specified = random.random(16)
                        },
                        iterationCount = iter or 4096,
                        prf = {type = ""}
                    }
                }
            }
        },
        encryptedData = ""
    }
    local hl
    if hasher == sha2.sha1 then
        pk8e.encryptionAlgorithm.pbes2Parameters.keyDerivationFunc.pbkdf2Parameters.prf.type = container.pseudoRandomFunctionOIDs.HMAC_SHA1
        hl = 20
    elseif hasher == sha2.sha224 then
        pk8e.encryptionAlgorithm.pbes2Parameters.keyDerivationFunc.pbkdf2Parameters.prf.type = container.pseudoRandomFunctionOIDs.HMAC_SHA224
        hl = 28
    elseif hasher == sha2.sha256 then
        pk8e.encryptionAlgorithm.pbes2Parameters.keyDerivationFunc.pbkdf2Parameters.prf.type = container.pseudoRandomFunctionOIDs.HMAC_SHA256
        hl = 32
    elseif hasher == sha2.sha384 then
        pk8e.encryptionAlgorithm.pbes2Parameters.keyDerivationFunc.pbkdf2Parameters.prf.type = container.pseudoRandomFunctionOIDs.HMAC_SHA384
        hl = 48
    elseif hasher == sha2.sha512 then
        pk8e.encryptionAlgorithm.pbes2Parameters.keyDerivationFunc.pbkdf2Parameters.prf.type = container.pseudoRandomFunctionOIDs.HMAC_SHA512
        hl = 64
    elseif hasher == sha2.sha512_224 then
        pk8e.encryptionAlgorithm.pbes2Parameters.keyDerivationFunc.pbkdf2Parameters.prf.type = container.pseudoRandomFunctionOIDs.HMAC_SHA512_224
        hl = 28
    elseif hasher == sha2.sha512_256 then
        pk8e.encryptionAlgorithm.pbes2Parameters.keyDerivationFunc.pbkdf2Parameters.prf.type = container.pseudoRandomFunctionOIDs.HMAC_SHA512_256
        hl = 32
    else error("Unknown hashing algorithm", 2) end
    local key = util.pbkdf2(function(d, k) return {sha2.hmac(hasher, k, string.char(table.unpack(d))):byte(1, -1)} end, hl, password, pk8e.encryptionAlgorithm.pbes2Parameters.keyDerivationFunc.pbkdf2Parameters.salt.specified, iter or 4096, 32)
    pk8e.encryptedData = aes.TableToString(aes.EncryptCBC(util.pkcs7pad(aes.StringToTable(data), 16), aes.StringToTable(key), aes.StringToTable(pk8e.encryptionAlgorithm.pbes2Parameters.encryptionScheme.iv)))
    return pk8e
end

--- Decrypts an encrypted PKCS#8 private key.
---@param pk8e EncryptedPrivateKeyInfo The key to decrypt
---@param password string The password to decrypt with
---@return PKCS8 pk8 The decrypted key
function crypto.decryptKey(pk8e, password)
    local hl, hasher, kl
    local ht = pk8e.encryptionAlgorithm.pbes2Parameters.keyDerivationFunc.pbkdf2Parameters.prf.type
    local et = pk8e.encryptionAlgorithm.pbes2Parameters.encryptionScheme.type
    if type(ht) == "table" then ht = ht.string end
    if type(et) == "table" then et = et.string end
    if ht == container.pseudoRandomFunctionOIDs.HMAC_SHA1 then
        hasher = sha2.sha1
        hl = 20
    elseif ht == container.pseudoRandomFunctionOIDs.HMAC_SHA224 then
        hasher = sha2.sha224
        hl = 28
    elseif ht == container.pseudoRandomFunctionOIDs.HMAC_SHA256 then
        hasher = sha2.sha256
        hl = 32
    elseif ht == container.pseudoRandomFunctionOIDs.HMAC_SHA384 then
        hasher = sha2.sha384
        hl = 48
    elseif ht == container.pseudoRandomFunctionOIDs.HMAC_SHA512 then
        hasher = sha2.sha512
        hl = 64
    elseif ht == container.pseudoRandomFunctionOIDs.HMAC_SHA512_224 then
        hasher = sha2.sha512_224
        hl = 28
    elseif ht == container.pseudoRandomFunctionOIDs.HMAC_SHA512_256 then
        hasher = sha2.sha512_256
        hl = 32
    else error("Unknown hashing algorithm", 2) end
    if et == container.encryptionAlgorithmOIDs.AES128_CBC then kl = 16
    elseif et == container.encryptionAlgorithmOIDs.AES192_CBC then kl = 24
    elseif et == container.encryptionAlgorithmOIDs.AES256_CBC then kl = 32
    else error("Unknown encryption algorithm", 2) end
    local key = util.pbkdf2(function(d, k) return {sha2.hmac(hasher, k, string.char(table.unpack(d))):byte(1, -1)} end, hl, password, pk8e.encryptionAlgorithm.pbes2Parameters.keyDerivationFunc.pbkdf2Parameters.salt.specified, pk8e.encryptionAlgorithm.pbes2Parameters.keyDerivationFunc.pbkdf2Parameters.iterationCount, kl)
    return container.loadPKCS8(aes.TableToString(util.pkcs7unpad(aes.DecryptCBC(aes.StringToTable(pk8e.encryptedData), aes.StringToTable(key), aes.StringToTable(pk8e.encryptionAlgorithm.pbes2Parameters.encryptionScheme.iv)))))
end

return crypto
