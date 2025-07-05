local container = require "cert.container"
local chain = require "cert.chain"
local util = require "cert.util"
local sha2 = require "sha2"
local ed25519 = require "ccryptolib.ed25519"

local signature = {}

--- Creates a PKCS#7 signature for the specified data, using the keys provided.
---@param cert X509 The certificate to sign with
---@param key PKCS8 The private key for the certificate
---@param data string|PKCS7 The data to sign
---@param additionalCerts? X509[] Any additional certificates needed to verify the signature (e.g. CA certificates)
---@return PKCS7SignedData pk7 The generated signature
function signature.sign(cert, key, data, additionalCerts)
    local ct = container.pkcs7ContentTypeOIDs.data
    if type(data) == "table" then
        ct = data.type
        data = container.savePKCS7(data)
    end
    assert(key.privateKeyAlgorithm.type.string == container.signatureAlgorithmOIDs.ED25519, "Private key must be Ed25519")
    assert(cert.toBeSigned.subjectPublicKeyInfo.algorithm.type.string == container.signatureAlgorithmOIDs.ED25519, "Certificate must be Ed25519")
    local now = os.date("!*t")
    now.type = "UTCTime"
    ---@type PKCS7Attribute[]
    local attrs = {
        {
            type = container.pkcs9AttributeOIDs.contentType,
            values = {
                contentType = ct
            }
        },
        {
            type = container.pkcs9AttributeOIDs.messageDigest,
            values = {
                messageDigest = sha2.hex_to_bin(sha2.sha3_512(data))
            }
        },
        {
            type = container.pkcs9AttributeOIDs.signingTime,
            values = {
                signingTime = {
                    utcTime = now
                }
            }
        }
    }
    local certs = {cert}
    if additionalCerts then for _, v in ipairs(additionalCerts) do certs[#certs+1] = v end end
    ---@type PKCS7SignedData
    local pk7 = {
        type = container.pkcs7ContentTypeOIDs.signedData,
        content = {
            version = 1,
            digestAlgorithms = {
                {
                    type = container.digestAlgorithmOIDs.SHA3_512
                }
            },
            encapContentInfo = {
                eContentType = ct,
                eContent = nil
            },
            certificates = certs,
            crls = nil,
            signerInfos = {
                {
                    version = 1,
                    sid = {
                        issuerAndSerialNumber = {
                            issuer = cert.toBeSigned.issuer,
                            serialNumber = cert.toBeSigned.serialNumber
                        }
                    },
                    digestAlgorithm = {
                        type = container.digestAlgorithmOIDs.SHA3_512,
                    },
                    signedAttrs = attrs,
                    signatureAlgorithm = {
                        type = container.signatureAlgorithmOIDs.ED25519,
                    },
                    signature = ed25519.sign(key.privateKey, cert.toBeSigned.subjectPublicKeyInfo.subjectPublicKey.data, container.encodePKCS7SignedAttrs(attrs))
                }
            }
        }
    }
    return pk7
end

--- Returns the certificate that signed a PKCS#7 data.
---@param pk7 PKCS7SignedData The signature to look in
---@param i number The index of the signed data to check
---@return X509|nil The certificate that signed that data, or nil if not found
function signature.getCertificate(pk7, i)
    local issuerName = util.reduceName(pk7.content.signerInfos[i].sid.issuerAndSerialNumber.issuer)
    for _, c in ipairs(pk7.content.certificates) do
        local name = util.reduceName(c.toBeSigned.issuer)
        local ok = true
        for k, s in pairs(issuerName) do if name[k] ~= s then ok = false break end end
        if ok and (c.toBeSigned.serialNumber == pk7.content.signerInfos[1].sid.issuerAndSerialNumber.serialNumber or c.toBeSigned.serialNumber.data == pk7.content.signerInfos[1].sid.issuerAndSerialNumber.serialNumber.data) then return c end
    end
    return nil
end

--- Verifies the signature of data using a PKCS#7 signature.
---@param pk7 PKCS7SignedData The signature of the original data
---@param data string The data to check
---@param index? number The index of the signed data in the signature (defaults to 1)
---@return boolean valid Whether the signature is valid
---@return string|nil reason If not valid, a reason why it's invalid
function signature.verify(pk7, data, index)
    index = index or 1
    if pk7.type.string ~= container.pkcs7ContentTypeOIDs.signedData then return false, "PKCS#7 block is not signed data" end
    if pk7.content.digestAlgorithms[1].type.string ~= container.digestAlgorithmOIDs.SHA3_512 then return false, "Unsupported digest algorithm" end
    if pk7.content.signerInfos[index].digestAlgorithm.type.string ~= container.digestAlgorithmOIDs.SHA3_512 then return false, "Unsupported digest algorithm" end
    if pk7.content.signerInfos[index].signatureAlgorithm.type.string ~= container.signatureAlgorithmOIDs.ED25519 then return false, "Unsupported signature algorithm" end
    local cert = signature.getCertificate(pk7, index)
    if not cert then return false, "Could not find certificate in signature" end
    local attrblock = container.encodePKCS7SignedAttrs(pk7.content.signerInfos[index].signedAttrs)
    if not ed25519.verify(cert.toBeSigned.subjectPublicKeyInfo.subjectPublicKey.data, attrblock, pk7.content.signerInfos[index].signature) then return false, "Failed to validate signature" end
    local sig
    for _, v in ipairs(pk7.content.signerInfos[index].signedAttrs) do if v.type.string == container.pkcs9AttributeOIDs.messageDigest then sig = v.values.messageDigest break end end
    if sha2.hex_to_bin(sha2.sha3_512(data)) ~= sig then return false, "Failed to validate digest" end
    return true
end

return signature
