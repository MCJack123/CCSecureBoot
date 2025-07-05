local expect = require "cc.expect"
local container = require "cert.container"
local ed25519 = require "ccryptolib.ed25519"
local x25519 = require "ccryptolib.x25519"

local csr = {}

--- Generates a certificate signature request (CSR) for a private key.
---@param pk8 PKCS8 The private key to generate a certificate for
---@param name Name The name of the subject of the certificate request
---@param attrs? Attribute[] Any attributes to attach to the certificate request
---@return PKCS10 pk10 A PKCS#10 certificate signature request
function csr.generate(pk8, name, attrs)
    expect(1, pk8, "table")
    expect(2, name, "table")
    expect(3, attrs, "table", "nil")
    local kt = pk8.privateKeyAlgorithm.type.string or pk8.privateKeyAlgorithm.type
    local pub
    if kt == container.signatureAlgorithmOIDs.ED25519 then pub = ed25519.publicKey(pk8.privateKey)
    elseif kt == container.publicKeyAlgorithmOIDs.X25519 then pub = x25519.publicKey(pk8.privateKey)
    else error("Unsupported private key algorithm", 2) end
    ---@type PKCS10
    local pk10 = {
        toBeSigned = {
            version = 0,
            subject = name,
            subjectPKInfo = {
                algorithm = pk8.privateKeyAlgorithm,
                subjectPublicKey = {type = "BIT STRING", data = pub, unused = 0}
            },
            attributes = attrs or {}
        },
        signatureAlgorithm = {type = container.signatureAlgorithmOIDs.ED25519},
        signature = {type = "BIT STRING", data = "", unused = 0}
    }
    pk10.signature.data = ed25519.sign(pk8.privateKey, ed25519.publicKey(pk8.privateKey), container.encodePKCS10InnerInfo(pk10))
    return pk10
end

--- Signs a certificate signature request, creating a new certificate.
---@param pk10 PKCS10 The CSR to sign
---@param cert X509 The certificate of the issuer
---@param pk8 PKCS8 The private key of the issuer
---@param serialNumber number|{type: "INTEGER", data: string} The serial number for the new certificate
---@param days number The number of days the certificate is valid for
---@param csrPublicKey? string If the CSR is for X25519 encryption, this must be the Ed25519 public key that was used for signing the CSR
---@return X509 outcert The new certificate for the request
function csr.sign(pk10, cert, pk8, serialNumber, days, csrPublicKey)
    expect(1, pk10, "table")
    expect(2, cert, "table")
    expect(3, pk8, "table")
    expect(4, serialNumber, "number", "table")
    expect(5, days, "number")
    local kt = pk8.privateKeyAlgorithm.type.string or pk8.privateKeyAlgorithm.type
    if kt ~= container.signatureAlgorithmOIDs.ED25519 and kt ~= container.publicKeyAlgorithmOIDs.X25519 then error("Unsupported private key algorithm", 2) end
    kt = cert.toBeSigned.subjectPublicKeyInfo.algorithm.type.string or cert.toBeSigned.subjectPublicKeyInfo.algorithm.type
    if kt ~= container.signatureAlgorithmOIDs.ED25519 then error("Unsupported certificate public key algorithm", 2) end
    kt = pk10.signatureAlgorithm.type.string or pk10.signatureAlgorithm.type
    if kt ~= container.signatureAlgorithmOIDs.ED25519 then error("Unsupported request signature algorithm", 2) end
    if not ed25519.verify(csrPublicKey or pk10.toBeSigned.subjectPKInfo.subjectPublicKey.data, container.encodePKCS10InnerInfo(pk10), pk10.signature.data) then error("Unable to verify request signature", 2) end
    local now = os.date("!*t")
    local exp = os.date("!*t", os.time() + days * 86400)
    ---@type X509
    local outcert = {
        toBeSigned = {
            version = 1,
            issuer = cert.toBeSigned.subject,
            serialNumber = serialNumber,
            signature = {type = container.signatureAlgorithmOIDs.ED25519},
            subject = pk10.toBeSigned.subject,
            subjectPublicKeyInfo = pk10.toBeSigned.subjectPKInfo,
            validity = {
                notBefore = {generalTime = now},
                notAfter = {generalTime = exp}
            }
        },
        signatureAlgorithm = {type = container.signatureAlgorithmOIDs.ED25519},
        signature = {type = "BIT STRING", data = "", unused = 0}
    }
    for _, v in ipairs(pk10.toBeSigned.attributes) do
        if (v.type.string or v.type) == container.pkcs9AttributeOIDs.extensionRequest then
            outcert.toBeSigned.version = 3
            outcert.toBeSigned.extensions = v.values.extensionRequest
        end
    end
    outcert.signature.data = ed25519.sign(pk8.privateKey, cert.toBeSigned.subjectPublicKeyInfo.subjectPublicKey.data, container.encodeX509InnerCertificate(outcert))
    return outcert
end

--- Self-signs a certificate signature request, creating a new certificate.
---@param pk10 PKCS10 The CSR to sign
---@param pk8 PKCS8 The private key of the CSR
---@param serialNumber number|{type: "INTEGER", data: string} The serial number for the new certificate
---@param days number The number of days the certificate is valid for
---@return X509 outcert The new certificate for the request
function csr.selfSign(pk10, pk8, serialNumber, days)
    expect(1, pk10, "table")
    expect(2, pk8, "table")
    expect(3, serialNumber, "number", "table")
    expect(4, days, "number")
    local kt = pk8.privateKeyAlgorithm.type.string or pk8.privateKeyAlgorithm.type
    if kt ~= container.signatureAlgorithmOIDs.ED25519 and kt ~= container.publicKeyAlgorithmOIDs.X25519 then error("Unsupported private key algorithm", 2) end
    kt = pk10.signatureAlgorithm.type.string or pk10.signatureAlgorithm.type
    if kt ~= container.signatureAlgorithmOIDs.ED25519 then error("Unsupported request signature algorithm", 2) end
    if not ed25519.verify(ed25519.publicKey(pk8.privateKey), container.encodePKCS10InnerInfo(pk10), pk10.signature.data) then error("Unable to verify request signature", 2) end
    local now = os.date("!*t")
    local exp = os.date("!*t", os.time() + days * 86400)
    ---@type X509
    local outcert = {
        toBeSigned = {
            version = 1,
            issuer = pk10.toBeSigned.subject,
            serialNumber = serialNumber,
            signature = {type = container.signatureAlgorithmOIDs.ED25519},
            subject = pk10.toBeSigned.subject,
            subjectPublicKeyInfo = pk10.toBeSigned.subjectPKInfo,
            validity = {
                notBefore = {generalTime = now},
                notAfter = {generalTime = exp}
            }
        },
        signatureAlgorithm = {type = container.signatureAlgorithmOIDs.ED25519},
        signature = {type = "BIT STRING", data = "", unused = 0}
    }
    for _, v in ipairs(pk10.toBeSigned.attributes) do
        if (v.type.string or v.type) == container.pkcs9AttributeOIDs.extensionRequest then
            outcert.toBeSigned.version = 3
            outcert.toBeSigned.extensions = v.values.extensionRequest
        end
    end
    outcert.signature.data = ed25519.sign(pk8.privateKey, ed25519.publicKey(pk8.privateKey), container.encodeX509InnerCertificate(outcert))
    return outcert
end

return csr
