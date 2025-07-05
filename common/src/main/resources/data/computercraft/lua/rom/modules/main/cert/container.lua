local expect = require "cc.expect"
local asn1 = require "asn1"

--- serialization.base64
-- @section serialization.base64

local b64str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

--- Encodes a binary string into Base64.
-- @tparam string str The string to encode
-- @treturn string The string's representation in Base64
local function base64_encode(str)
    expect(1, str, "string")
    local retval = ""
    for s in str:gmatch "..." do
        local n = s:byte(1) * 65536 + s:byte(2) * 256 + s:byte(3)
        local a, b, c, d = bit32.extract(n, 18, 6), bit32.extract(n, 12, 6), bit32.extract(n, 6, 6), bit32.extract(n, 0, 6)
        retval = retval .. b64str:sub(a+1, a+1) .. b64str:sub(b+1, b+1) .. b64str:sub(c+1, c+1) .. b64str:sub(d+1, d+1)
    end
    if #str % 3 == 1 then
        local n = str:byte(-1)
        local a, b = bit32.rshift(n, 2), bit32.lshift(bit32.band(n, 3), 4)
        retval = retval .. b64str:sub(a+1, a+1) .. b64str:sub(b+1, b+1) .. "=="
    elseif #str % 3 == 2 then
        local n = str:byte(-2) * 256 + str:byte(-1)
        local a, b, c = bit32.extract(n, 10, 6), bit32.extract(n, 4, 6), bit32.lshift(bit32.extract(n, 0, 4), 2)
        retval = retval .. b64str:sub(a+1, a+1) .. b64str:sub(b+1, b+1) .. b64str:sub(c+1, c+1) .. "="
    end
    return retval
end

--- Decodes a Base64 string to binary.
-- @tparam string str The Base64 to decode
-- @treturn string The decoded data
local function base64_decode(str)
    expect(1, str, "string")
    local retval = ""
    for s in str:gmatch "...." do
        if s:sub(3, 4) == '==' then
            retval = retval .. string.char(bit32.bor(bit32.lshift(b64str:find(s:sub(1, 1)) - 1, 2), bit32.rshift(b64str:find(s:sub(2, 2)) - 1, 4)))
        elseif s:sub(4, 4) == '=' then
            local n = (b64str:find(s:sub(1, 1))-1) * 4096 + (b64str:find(s:sub(2, 2))-1) * 64 + (b64str:find(s:sub(3, 3))-1)
            retval = retval .. string.char(bit32.extract(n, 10, 8)) .. string.char(bit32.extract(n, 2, 8))
        else
            local n = (b64str:find(s:sub(1, 1))-1) * 262144 + (b64str:find(s:sub(2, 2))-1) * 4096 + (b64str:find(s:sub(3, 3))-1) * 64 + (b64str:find(s:sub(4, 4))-1)
            retval = retval .. string.char(bit32.extract(n, 16, 8)) .. string.char(bit32.extract(n, 8, 8)) .. string.char(bit32.extract(n, 0, 8))
        end
    end
    return retval
end

local container = {}

container.nameOIDs = {
    commonName = "2.5.4.3",
    countryName = "2.5.4.6",
    localityName = "2.5.4.7",
    stateOrProvinceName = "2.5.4.8",
    streetAddress = "2.5.4.9",
    organizationIdentifier = "2.5.4.97",
    organizationName = "2.5.4.10",
    organizationalUnitName = "2.5.4.11",
    serialNumber = "2.5.4.5",
    surname = "2.5.4.4",
    givenName = "2.5.4.42",
    title = "2.5.4.12",
    initials = "2.5.4.43",
    generationQualifier = "2.5.4.44",
    uniqueIdentifier = "2.5.4.45",
    dnQualifier = "2.5.4.46",
    pseudonym = "2.5.4.65",
    userID = "0.9.2342.19200300.100.1.1",
    domainComponent = "0.9.2342.19200300.100.1.25",
    emailAddress = "1.2.840.113549.1.9.1",
    jurisdictionLocalityName = "1.3.6.1.4.1.311.60.2.1.1",
    jurisdictionStateOrProvinceName = "1.3.6.1.4.1.311.60.2.1.2",
    jurisdictionCountryName = "1.3.6.1.4.1.311.60.2.1.3",
    businessCategory = "2.5.4.15",
    postalAddress = "1.5.4.16",
    postalCode = "1.5.4.17",
    unstructuredName = "1.2.840.113549.1.9.2"
}

container.signatureAlgorithmOIDs = {
    RSA_MD5 = "1.2.840.113549.1.1.4",
    RSA_SHA1 = "1.2.840.113549.1.1.5",
    RSA_SHA224 = "1.2.840.113549.1.1.14",
    RSA_SHA256 = "1.2.840.113549.1.1.11",
    RSA_SHA384 = "1.2.840.113549.1.1.12",
    RSA_SHA512 = "1.2.840.113549.1.1.13",
    RSA_SHA3_224 = "2.16.840.1.101.3.4.3.13",
    RSA_SHA3_256 = "2.16.840.1.101.3.4.3.14",
    RSA_SHA3_384 = "2.16.840.1.101.3.4.3.15",
    RSA_SHA3_512 = "2.16.840.1.101.3.4.3.16",
    RSASSA_PSS = "1.2.840.113549.1.1.10",
    ECDSA_SHA1 = "1.2.840.10045.4.1",
    ECDSA_SHA224 = "1.2.840.10045.4.3.1",
    ECDSA_SHA256 = "1.2.840.10045.4.3.2",
    ECDSA_SHA384 = "1.2.840.10045.4.3.3",
    ECDSA_SHA512 = "1.2.840.10045.4.3.4",
    ECDSA_SHA3_224 = "2.16.840.1.101.3.4.3.9",
    ECDSA_SHA3_256 = "2.16.840.1.101.3.4.3.10",
    ECDSA_SHA3_384 = "2.16.840.1.101.3.4.3.11",
    ECDSA_SHA3_512 = "2.16.840.1.101.3.4.3.12",
    DSA_SHA1 = "1.2.840.10040.4.3",
    DSA_SHA224 = "2.16.840.1.101.3.4.3.1",
    DSA_SHA256 = "2.16.840.1.101.3.4.3.2",
    DSA_SHA384 = "2.16.840.1.101.3.4.3.3",
    DSA_SHA512 = "2.16.840.1.101.3.4.3.4",
    ED25519 = "1.3.101.112",
    ED448 = "1.3.101.113"
}

container.extendedKeyUsageOIDs = {
    serverAuth = "1.3.6.1.5.5.7.3.1",
    clientAuth = "1.3.6.1.5.5.7.3.2",
    codeSigning = "1.3.6.1.5.5.7.3.3",
    emailProtection = "1.3.6.1.5.5.7.3.4",
    timeStamping = "1.3.6.1.5.5.7.3.8",
    ocspSigning = "1.3.6.1.5.5.7.3.9",
    anyExtendedKeyUsage = "2.5.29.37.0",
    smartcardLogon = "1.3.6.1.4.1.311.20.2.2",
    kerberosPKInitKDC = "1.3.6.1.5.2.3.5",
    IPSec_IKE = "1.3.6.1.5.5.7.3.17",
    certificateTransparency = "1.3.6.1.4.1.11129.2.4.4"
}

container.extensionOIDs = {
    basicConstraints = "2.5.29.19",
    keyUsage = "2.5.29.15",
    subjectAlternativeName = "2.5.29.17",
    issuerAlternativeName = "2.5.29.18",
    subjectKeyIdentifier = "2.5.29.14",
    nameConstraints = "2.5.29.30",
    crlDistributionPoints = "2.5.29.31",
    -- ...
}

container.publicKeyAlgorithmOIDs = {
    DSA = "1.2.840.10040.4.1",
    EC_PUBLIC_KEY = "1.2.840.10045.2.1",
    RSAES_PKCS1v15 = "1.2.840.113549.1.1.1",
    RSASSA_PSS = "1.2.840.113549.1.1.10",
    X25519 = "1.3.101.110",
    X448 = "1.3.101.111",
    ED25519 = "1.3.101.112",
    ED448 = "1.3.101.113"
}

container.digestAlgorithmOIDs = {
    SHA1 = "1.3.14.3.2.26",
    SHA224 = "2.16.840.1.101.3.4.2.4",
    SHA256 = "2.16.840.1.101.3.4.2.1",
    SHA384 = "2.16.840.1.101.3.4.2.2",
    SHA512 = "2.16.840.1.101.3.4.2.3",
    SHA3_224 = "2.16.840.1.101.3.4.2.7",
    SHA3_256 = "2.16.840.1.101.3.4.2.8",
    SHA3_384 = "2.16.840.1.101.3.4.2.9",
    SHA3_512 = "2.16.840.1.101.3.4.2.10",
}

container.encryptionAlgorithmOIDs = {
    AES128_CBC = "2.16.840.1.101.3.4.1.2",
    AES192_CBC = "2.16.840.1.101.3.4.1.22",
    AES256_CBC = "2.16.840.1.101.3.4.1.42",
    ChaCha20_Poly1305 = "1.2.840.113549.1.9.16.0.66"
}

container.keyDerivationAlgorithmOIDs = {
    PBKDF2 = "1.2.840.113549.1.5.12"
}

container.passwordBasedEncryptionSchemeOIDs = {
    PBES2 = "1.2.840.113549.1.5.13"
}

container.pseudoRandomFunctionOIDs = {
    HMAC_SHA1 = "1.2.840.113549.2.7",
    HMAC_SHA224 = "1.2.840.113549.2.8",
    HMAC_SHA256 = "1.2.840.113549.2.9",
    HMAC_SHA384 = "1.2.840.113549.2.10",
    HMAC_SHA512 = "1.2.840.113549.2.11",
    HMAC_SHA512_224 = "1.2.840.113549.2.12",
    HMAC_SHA512_256 = "1.2.840.113549.2.13",
}

---@class ObjectIdentifierObj
---@field string string

---@alias ObjectIdentifier ObjectIdentifierObj|string

---@class bit_string
---@field type "BIT STRING"
---@field data string
---@field unused number

-- X.509 --

---@class FieldID
---@field fieldType ObjectIdentifier
---@field parameters any|nil

local FieldID = asn1.sequence {
    {"fieldType", asn1.oid},
    {"parameters", asn1.optional(asn1.any)}
}

---@class Curve
---@field a string
---@field b string
---@field seed bit_string|nil

local Curve = asn1.sequence {
    {"a", asn1.octet_string},
    {"b", asn1.octet_string},
    {"seed", asn1.optional(asn1.bit_string)}
}

---@class ECParameters
---@field version number
---@field fieldID FieldID
---@field curve Curve
---@field base string
---@field order number
---@field cofactor number|nil

local ECParameters = asn1.sequence {
    {"version", asn1.integer},
    {"fieldID", FieldID},
    {"curve", Curve},
    {"base", asn1.octet_string},
    {"order", asn1.integer},
    {"cofactor", asn1.optional(asn1.integer)}
}

---@class EcpkParameters
---@field ecParameters ECParameters
---@field namedCurve ObjectIdentifier
---@field implicitlyCA nil

local EcpkParameters = asn1.choice {
    {"ecParameters", ECParameters},
    {"namedCurve", asn1.oid},
    {"implicitlyCA", asn1.null}
}

---@class AlgorithmIdentifier
---@field type ObjectIdentifier
---@field ecParameters EcpkParameters|nil
---@field pbes2Parameters PBES2_Params|nil
---@field pbkdf2Parameters PBKDF2_Params|nil
---@field iv string|nil
---@field nonce string|nil

local algorithm_list = {
    [container.publicKeyAlgorithmOIDs.EC_PUBLIC_KEY] = {{"ecParameters", EcpkParameters}},
    [container.signatureAlgorithmOIDs.ECDSA_SHA1] = {},
    [container.signatureAlgorithmOIDs.ECDSA_SHA224] = {},
    [container.signatureAlgorithmOIDs.ECDSA_SHA256] = {},
    [container.signatureAlgorithmOIDs.ECDSA_SHA384] = {},
    [container.signatureAlgorithmOIDs.ECDSA_SHA512] = {},
    [container.signatureAlgorithmOIDs.ECDSA_SHA3_224] = {},
    [container.signatureAlgorithmOIDs.ECDSA_SHA3_256] = {},
    [container.signatureAlgorithmOIDs.ECDSA_SHA3_384] = {},
    [container.signatureAlgorithmOIDs.ECDSA_SHA3_512] = {},
    [container.signatureAlgorithmOIDs.ED25519] = {{"parameters", asn1.optional(asn1.null)}},
    [container.publicKeyAlgorithmOIDs.X25519] = {},
    [container.digestAlgorithmOIDs.SHA1] = {},
    [container.digestAlgorithmOIDs.SHA224] = {},
    [container.digestAlgorithmOIDs.SHA256] = {},
    [container.digestAlgorithmOIDs.SHA384] = {},
    [container.digestAlgorithmOIDs.SHA512] = {},
    [container.digestAlgorithmOIDs.SHA3_224] = {},
    [container.digestAlgorithmOIDs.SHA3_256] = {},
    [container.digestAlgorithmOIDs.SHA3_384] = {},
    [container.digestAlgorithmOIDs.SHA3_512] = {{"parameters", asn1.optional(asn1.null)}},
    [container.encryptionAlgorithmOIDs.AES128_CBC] = {{"iv", asn1.octet_string}},
    [container.encryptionAlgorithmOIDs.AES192_CBC] = {{"iv", asn1.octet_string}},
    [container.encryptionAlgorithmOIDs.AES256_CBC] = {{"iv", asn1.octet_string}},
    [container.encryptionAlgorithmOIDs.ChaCha20_Poly1305] = {{"nonce", asn1.octet_string}},
    [container.pseudoRandomFunctionOIDs.HMAC_SHA1] = {},
    [container.pseudoRandomFunctionOIDs.HMAC_SHA224] = {},
    [container.pseudoRandomFunctionOIDs.HMAC_SHA256] = {},
    [container.pseudoRandomFunctionOIDs.HMAC_SHA384] = {},
    [container.pseudoRandomFunctionOIDs.HMAC_SHA512] = {},
    [container.pseudoRandomFunctionOIDs.HMAC_SHA512_224] = {},
    [container.pseudoRandomFunctionOIDs.HMAC_SHA512_256] = {},
}

local AlgorithmIdentifier = asn1.class(algorithm_list)

---@generic ToBeSigned
---@class Signed<ToBeSigned>: {toBeSigned: ToBeSigned, signatureAlgorithm: AlgorithmIdentifier, signature: bit_string}
local function Signed(ToBeSigned) return asn1.sequence {
    {"toBeSigned", ToBeSigned},
    {"signatureAlgorithm", AlgorithmIdentifier},
    {"signature", asn1.bit_string}
} end

---@class UnboundedDirectoryString
---@field teletexString string|nil
---@field printableString string|nil
---@field bmptring string|nil
---@field universalString string|nil
---@field uTF8String string|nil

local UnboundedDirectoryString = asn1.choice {
    {"teletexString", asn1.teletex_string},
    {"printableString", asn1.printable_string},
    {"bmpString", asn1.bmp_string},
    {"universalString", asn1.universal_string},
    {"uTF8String", asn1.utf8string}
}

---@class AttributeTypeAndValue
---@field type ObjectIdentifier
---@field value UnboundedDirectoryString|string

local AttributeTypeAndValue = asn1.class {
    [container.nameOIDs.commonName] = {{"value", UnboundedDirectoryString}},
    [container.nameOIDs.surname] = {{"value", UnboundedDirectoryString}},
    [container.nameOIDs.givenName] = {{"value", UnboundedDirectoryString}},
    [container.nameOIDs.initials] = {{"value", UnboundedDirectoryString}},
    [container.nameOIDs.generationQualifier] = {{"value", UnboundedDirectoryString}},
    [container.nameOIDs.uniqueIdentifier] = {{"value", asn1.octet_string}},
    [container.nameOIDs.dnQualifier] = {{"value", asn1.printable_string}},
    [container.nameOIDs.serialNumber] = {{"value", asn1.printable_string}},
    [container.nameOIDs.pseudonym] = {{"value", UnboundedDirectoryString}},
    [container.nameOIDs.countryName] = {{"value", asn1.printable_string}},
    [container.nameOIDs.localityName] = {{"value", UnboundedDirectoryString}},
    [container.nameOIDs.jurisdictionLocalityName] = {{"value", UnboundedDirectoryString}},
    [container.nameOIDs.stateOrProvinceName] = {{"value", UnboundedDirectoryString}},
    [container.nameOIDs.jurisdictionStateOrProvinceName] = {{"value", UnboundedDirectoryString}},
    [container.nameOIDs.streetAddress] = {{"value", UnboundedDirectoryString}},
    [container.nameOIDs.organizationName] = {{"value", UnboundedDirectoryString}},
    [container.nameOIDs.organizationalUnitName] = {{"value", UnboundedDirectoryString}},
    [container.nameOIDs.title] = {{"value", UnboundedDirectoryString}},
    [container.nameOIDs.organizationIdentifier] = {{"value", UnboundedDirectoryString}},
    [container.nameOIDs.businessCategory] = {{"value", UnboundedDirectoryString}},
    [container.nameOIDs.postalAddress] = {{"value", UnboundedDirectoryString}},
    [container.nameOIDs.postalCode] = {{"value", UnboundedDirectoryString}},
}

---@alias RelativeDistinguishedName AttributeTypeAndValue[]
local RelativeDistinguishedName = asn1.set_of(AttributeTypeAndValue)

---@alias RDNSequence RelativeDistinguishedName[]
local RDNSequence = asn1.sequence_of(RelativeDistinguishedName)

---@class Name
---@field rdnSequence RDNSequence

local Name = asn1.choice {
    {"rdnSequence", RDNSequence}
}

---@class Time
---@field utcTime osdate|nil
---@field generalTime osdate|nil

local Time = asn1.choice {
    {"utcTime", asn1.utc_time},
    {"generalTime", asn1.generalized_time}
}

---@class Validity
---@field notBefore Time
---@field notAfter Time

local Validity = asn1.sequence {
    {"notBefore", Time},
    {"notAfter", Time}
}

---@class SubjectPublicKeyInfo
---@field algorithm AlgorithmIdentifier
---@field subjectPublicKey bit_string

local SubjectPublicKeyInfo = asn1.sequence {
    {"algorithm", AlgorithmIdentifier},
    {"subjectPublicKey", asn1.bit_string}
}

---@class Extension
---@field extnId ObjectIdentifier
---@field critical boolean|nil
---@field extnValue string

local Extension = asn1.sequence {
    {"extnId", asn1.oid},
    {"critical", asn1.optional(asn1.boolean)},
    {"extnValue", asn1.octet_string}
}

---@class TBSCertificate
---@field version number
---@field serialNumber {type: "INTEGER", data: string}|number
---@field signature AlgorithmIdentifier
---@field issuer Name
---@field validity Validity
---@field subject Name
---@field subjectPublicKeyInfo SubjectPublicKeyInfo
---@field issuerUniqueID bit_string|nil
---@field subjectUniqueID bit_string|nil
---@field extensions Extension[]|nil

local TBSCertificate = asn1.sequence {
    {"version", asn1.default(asn1.explicit(0, asn1.integer), 1)},
    {"serialNumber", asn1.integer},
    {"signature", AlgorithmIdentifier},
    {"issuer", Name},
    {"validity", Validity},
    {"subject", Name},
    {"subjectPublicKeyInfo", SubjectPublicKeyInfo},
    {"issuerUniqueID", asn1.optional(asn1.implicit(1, asn1.bit_string))},
    {"subjectUniqueID", asn1.optional(asn1.implicit(2, asn1.bit_string))},
    {"extensions", asn1.optional(asn1.explicit(3, asn1.sequence_of(Extension)))}
}

---@alias Certificate Signed<TBSCertificate>
local Certificate = Signed(TBSCertificate)

---@class CertificateListContent
---@field version number
---@field signature AlgorithmIdentifier
---@field issuer Name
---@field thisUpdate Time
---@field nextUpdate Time|nil
---@field revokedCertificates {serialNumber: {type: "INTEGER", data: string}|number, revocationDate: Time, crlEntryExtensions: Extension[]|nil}[]|nil
---@field crlExtensions Extension[]|nil

local CertificateListContent = asn1.sequence {
    {"version", asn1.optional(asn1.integer)},
    {"signature", AlgorithmIdentifier},
    {"issuer", Name},
    {"thisUpdate", Time},
    {"nextUpdate", asn1.optional(Time)},
    {"revokedCertificates", asn1.optional(asn1.sequence_of(asn1.sequence {
        {"serialNumber", asn1.integer},
        {"revocationDate", Time},
        {"crlEntryExtensions", asn1.optional(asn1.sequence_of(Extension))}
    }))},
    {"crlExtensions", asn1.optional(asn1.explicit(0, asn1.sequence_of(Extension)))}
}

---@alias CertificateList Signed<CertificateListContent>
local CertificateList = Signed(CertificateListContent)

---@alias X509 Certificate
---@alias X509CRL CertificateList

-- PKCS#9 --

container.pkcs9AttributeOIDs = {
    emailAddress = "1.2.840.113549.1.9.1",
    unstructuredName = "1.2.840.113549.1.9.2",
    contentType = "1.2.840.113549.1.9.3",
    messageDigest = "1.2.840.113549.1.9.4",
    signingTime = "1.2.840.113549.1.9.5",
    countersignature = "1.2.840.113549.1.9.6",
    challengePassword = "1.2.840.113549.1.9.7",
    unstructuredAddress = "1.2.840.113549.1.9.8",
    extendedCertificateAttributes = "1.2.840.113549.1.9.9",
    signingDescription = "1.2.840.113549.1.9.13",
    extensionRequest = "1.2.840.113549.1.9.14",
    smimeCapabilities = "1.2.840.113549.1.9.15",
    friendlyName = "1.2.840.113549.1.9.20",
    localKeyId = "1.2.840.113549.1.9.21",
    userPKCS12 = "2.16.840.1.113730.3.1.216",
    pkcs15Token = "1.2.840.113549.1.9.25.1",
    encryptedPrivateKeyInfo = "1.2.840.113549.1.9.25.2",
    randomNonce = "1.2.840.113549.1.9.25.3",
    sequenceNumber = "1.2.840.113549.1.9.25.4",
    pkcs7PDU = "1.2.840.113549.1.9.25.5",
    dateOfBirth = "1.3.6.1.5.5.7.9.1",
    placeOfBirth = "1.3.6.1.5.5.7.9.2",
    gender = "1.3.6.1.5.5.7.9.3",
    countryOfCitizenship = "1.3.6.1.5.5.7.9.4",
    countryOfResidence = "1.3.6.1.5.5.7.9.5",
    pseudonym = "2.5.4.65",
}

---@class PKCS9String
---@field ia5string string|nil
---@field directoryString UnboundedDirectoryString|nil

local PKCS9String = asn1.choice {
    {"ia5string", asn1.ia5string},
    {"directoryString", UnboundedDirectoryString}
}

local PKCS9AttributeList = {
    [container.pkcs9AttributeOIDs.emailAddress] = {{"values", asn1.set {{"emailAddress", asn1.ia5string}}}},
    [container.pkcs9AttributeOIDs.unstructuredName] = {{"values", asn1.set {{"unstructuredName", PKCS9String}}}},
    [container.pkcs9AttributeOIDs.unstructuredAddress] = {{"values", asn1.set {{"unstructuredAddress", UnboundedDirectoryString}}}},
    [container.pkcs9AttributeOIDs.dateOfBirth] = {{"values", asn1.set {{"dateOfBirth", asn1.generalized_time}}}},
    [container.pkcs9AttributeOIDs.placeOfBirth] = {{"values", asn1.set {{"placeOfBirth", UnboundedDirectoryString}}}},
    [container.pkcs9AttributeOIDs.gender] = {{"values", asn1.set {{"gender", asn1.printable_string}}}},
    [container.pkcs9AttributeOIDs.countryOfCitizenship] = {{"values", asn1.set {{"countryOfCitizenship", asn1.printable_string}}}},
    [container.pkcs9AttributeOIDs.countryOfResidence] = {{"values", asn1.set {{"countryOfResidence", asn1.printable_string}}}},
    [container.pkcs9AttributeOIDs.pseudonym] = {{"values", asn1.set {{"pseudonym", UnboundedDirectoryString}}}},
    [container.pkcs9AttributeOIDs.contentType] = {{"values", asn1.set {{"contentType", asn1.oid}}}},
    [container.pkcs9AttributeOIDs.messageDigest] = {{"values", asn1.set {{"messageDigest", asn1.octet_string}}}},
    [container.pkcs9AttributeOIDs.signingTime] = {{"values", asn1.set {{"signingTime", Time}}}},
    [container.pkcs9AttributeOIDs.randomNonce] = {{"values", asn1.set {{"randomNonce", asn1.octet_string}}}},
    [container.pkcs9AttributeOIDs.sequenceNumber] = {{"values", asn1.set {{"sequenceNumber", asn1.integer}}}},
    [container.pkcs9AttributeOIDs.challengePassword] = {{"values", asn1.set {{"challengePassword", UnboundedDirectoryString}}}},
    [container.pkcs9AttributeOIDs.extensionRequest] = {{"values", asn1.set {{"extensionRequest", asn1.sequence_of(Extension)}}}},
    [container.pkcs9AttributeOIDs.friendlyName] = {{"values", asn1.set {{"friendlyName", asn1.bmp_string}}}},
    [container.pkcs9AttributeOIDs.localKeyId] = {{"values", asn1.set {{"localKeyId", asn1.octet_string}}}},
    [container.pkcs9AttributeOIDs.signingDescription] = {{"values", asn1.set {{"signingDescription", UnboundedDirectoryString}}}},
    [container.pkcs9AttributeOIDs.smimeCapabilities] = {{"values", asn1.set {{"smimeCapabilities", asn1.sequence_of(AlgorithmIdentifier)}}}},
}

---@class Attribute
---@field type ObjectIdentifier
---@field values any

---@class ContentTypeAttribute: Attribute
---@field values {contentType: ObjectIdentifier}

---@class MessageDigestAttribute: Attribute
---@field values {messageDigest: string}

---@class SigningTimeAttribute: Attribute
---@field values {signingTime: Time}

---@class CountersignatureAttribute: Attribute
---@field values {countersignature: SignerInfo}

local Attribute = asn1.class(PKCS9AttributeList)

PKCS9AttributeList[container.pkcs9AttributeOIDs.extendedCertificateAttributes] = {{"values", asn1.set {{"extendedCertificateAttributes", asn1.set_of(Attribute)}}}}

-- PKCS#10 --

---@class CertificationRequestInfo
---@field version number
---@field subject Name
---@field subjectPKInfo SubjectPublicKeyInfo
---@field attributes Attribute[]

local CertificationRequestInfo = asn1.sequence {
    {"version", asn1.integer},
    {"subject", Name},
    {"subjectPKInfo", SubjectPublicKeyInfo},
    {"attributes", asn1.implicit(0, asn1.set_of(Attribute))}
}

---@alias CertificationRequest Signed<CertificationRequestInfo>
local CertificationRequest = Signed(CertificationRequestInfo)

---@alias PKCS10 CertificationRequest

-- PKCS#8 --

---@class EncryptedPrivateKeyInfo
---@field encryptionAlgorithm AlgorithmIdentifier
---@field encryptedData string

local EncryptedPrivateKeyInfo = asn1.sequence {
    {"encryptionAlgorithm", AlgorithmIdentifier},
    {"encryptedData", asn1.octet_string}
}

PKCS9AttributeList[container.pkcs9AttributeOIDs.encryptedPrivateKeyInfo] = {{"values", asn1.set {{"encryptedPrivateKeyInfo", EncryptedPrivateKeyInfo}}}}

---@class PrivateKeyInfo
---@field version number
---@field privateKeyAlgorithm AlgorithmIdentifier
---@field privateKey string
---@field attributes Attribute[]|nil

local PrivateKeyInfo = asn1.sequence {
    {"version", asn1.integer},
    {"privateKeyAlgorithm", AlgorithmIdentifier},
    {"privateKey", asn1.octet_string},
    {"attributes", asn1.optional(asn1.set_of(Attribute))}
}

---@alias PKCS8 PrivateKeyInfo
---@alias PKCS8Encrypted EncryptedPrivateKeyInfo

-- PKCS#7 --

container.pkcs7ContentTypeOIDs = {
    data = "1.2.840.113549.1.7.1",
    signedData = "1.2.840.113549.1.7.2",
    envelopedData = "1.2.840.113549.1.7.3",
    digestedData = "1.2.840.113549.1.7.5",
    encryptedData = "1.2.840.113549.1.7.6",
    authData = "1.2.840.113549.1.9.16.1.2",
    authEnvelopedData = "1.2.840.113549.1.9.16.1.23",
}

--- Signed data

---@class EncapsulatedContentInfo
---@field eContentType ObjectIdentifier
---@field eContent string|nil

local EncapsulatedContentInfo = asn1.sequence {
    {"eContentType", asn1.oid},
    {"eContent", asn1.optional(asn1.explicit(0, asn1.octet_string))}
}

---@class IssuerAndSerialNumber
---@field issuer Name
---@field serialNumber {type: "INTEGER", data: string}|number

local IssuerAndSerialNumber = asn1.sequence {
    {"issuer", Name},
    {"serialNumber", asn1.integer}
}

---@class SignerIdentifier
---@field issuerAndSerialNumber IssuerAndSerialNumber|nil
---@field subjectKeyIdentifier string|nil

local SignerIdentifier = asn1.choice {
    {"issuerAndSerialNumber", IssuerAndSerialNumber},
    {"subjectKeyIdentifier", asn1.explicit(0, asn1.octet_string)}
}

---@class SignerInfo
---@field version number
---@field sid SignerIdentifier
---@field digestAlgorithm AlgorithmIdentifier
---@field signedAttrs Attribute[]|nil
---@field signatureAlgorithm AlgorithmIdentifier
---@field signature string
---@field unsignedAttrs Attribute[]|nil

local SignerInfo = asn1.sequence {
    {"version", asn1.integer},
    {"sid", SignerIdentifier},
    {"digestAlgorithm", AlgorithmIdentifier},
    {"signedAttrs", asn1.optional(asn1.implicit(0, asn1.set_of(Attribute)))},
    {"signatureAlgorithm", AlgorithmIdentifier},
    {"signature", asn1.octet_string},
    {"unsignedAttrs", asn1.optional(asn1.implicit(1, asn1.set_of(Attribute)))}
}

PKCS9AttributeList[container.pkcs9AttributeOIDs.countersignature] = {{"countersignature", SignerInfo}}

---@class SignedData
---@field version number
---@field digestAlgorithms AlgorithmIdentifier[]
---@field encapContentInfo EncapsulatedContentInfo
---@field certificates Certificate[]|nil
---@field crls CertificateList[]|nil
---@field signerInfos SignerInfo[]

local SignedData = asn1.sequence {
    {"version", asn1.integer},
    {"digestAlgorithms", asn1.set_of(AlgorithmIdentifier)},
    {"encapContentInfo", EncapsulatedContentInfo},
    {"certificates", asn1.optional(asn1.implicit(0, asn1.set_of(Certificate)))},
    {"crls", asn1.optional(asn1.implicit(1, asn1.set_of(CertificateList)))},
    {"signerInfos", asn1.set_of(SignerInfo)}
}

--- Enveloped data

---@class OriginatorInfo
---@field certs Certificate[]|nil
---@field crls CertificateList[]|nil

local OriginatorInfo = asn1.sequence {
    {"certs", asn1.optional(asn1.implicit(0, asn1.set_of(Certificate)))},
    {"crls", asn1.optional(asn1.implicit(1, asn1.set_of(CertificateList)))}
}

---@class KeyTransRecipientInfo
---@field version number
---@field rid SignerIdentifier
---@field keyEncryptionAlgorithm AlgorithmIdentifier
---@field encryptedKey string

local KeyTransRecipientInfo = asn1.sequence {
    {"version", asn1.integer},
    {"rid", SignerIdentifier},
    {"keyEncryptionAlgorithm", AlgorithmIdentifier},
    {"encryptedKey", asn1.octet_string}
}

---@class OriginatorIdentifierOrKey
---@field issuerAndSerialNumber IssuerAndSerialNumber|nil
---@field subjectKeyIdentifier {type: "INTEGER", data: string}|number|nil
---@field originatorKey {algorithm: AlgorithmIdentifier, publicKey: bit_string}|nil

local OriginatorIdentifierOrKey = asn1.choice {
    {"issuerAndSerialNumber", IssuerAndSerialNumber},
    {"subjectKeyIdentifier", asn1.explicit(0, asn1.integer)},
    {"originatorKey", asn1.explicit(1, asn1.sequence {
        {"algorithm", AlgorithmIdentifier},
        {"publicKey", asn1.bit_string}
    })}
}

---@class OtherKeyAttribute
---@field type ObjectIdentifier
---@field value any

local OtherKeyAttribute = asn1.sequence {
    {"type", asn1.oid},
    {"value", asn1.any}
}

---@class RecipientKeyIdentifier
---@field subjectKeyIdentifier string
---@field date osdate|nil
---@field other OtherKeyAttribute|nil

local RecipientKeyIdentifier = asn1.sequence {
    {"subjectKeyIdentifier", asn1.octet_string},
    {"date", asn1.optional(asn1.generalized_time)},
    {"other", asn1.optional(OtherKeyAttribute)}
}

---@class KeyAgreementRecipientIdentifier
---@field issuerAndSerialNumber IssuerAndSerialNumber|nil
---@field rKeyID RecipientKeyIdentifier|nil

local KeyAgreementRecipientIdentifier = asn1.choice {
    {"issuerAndSerialNumber", IssuerAndSerialNumber},
    {"rKeyId", asn1.implicit(0, RecipientKeyIdentifier)}
}

---@class RecipientEncryptedKey
---@field rid KeyAgreementRecipientIdentifier
---@field encryptedKey string

local RecipientEncryptedKey = asn1.sequence {
    {"rid", KeyAgreementRecipientIdentifier},
    {"encryptedKey", asn1.octet_string}
}

---@class KeyAgreeRecipientInfo
---@field version number
---@field originator OriginatorIdentifierOrKey
---@field ukm string|nil
---@field keyEncryptionAlgorithm AlgorithmIdentifier
---@field recipientEncryptedKeys RecipientEncryptedKey[]

local KeyAgreeRecipientInfo = asn1.sequence {
    {"version", asn1.integer},
    {"originator", asn1.explicit(0, OriginatorIdentifierOrKey)},
    {"ukm", asn1.optional(asn1.explicit(1, asn1.octet_string))},
    {"keyEncryptionAlgorithm", AlgorithmIdentifier},
    {"recipientEncryptedKeys", asn1.sequence_of(RecipientEncryptedKey)}
}

---@class KEKRecipientInfo
---@field version number
---@field kekid RecipientKeyIdentifier
---@field keyEncryptionAlgorithm AlgorithmIdentifier
---@field encryptedKey string

local KEKRecipientInfo = asn1.sequence {
    {"version", asn1.integer},
    {"kekid", RecipientKeyIdentifier},
    {"keyEncryptionAlgorithm", AlgorithmIdentifier},
    {"encryptedKey", asn1.octet_string}
}

---@class PasswordRecipientInfo
---@field version number
---@field keyDerivationAlgorithm AlgorithmIdentifier|nil
---@field keyEncryptionAlgorithm AlgorithmIdentifier
---@field encryptedKey string

local PasswordRecipientInfo = asn1.sequence {
    {"version", asn1.integer},
    {"keyDerivationAlgorithm", asn1.optional(asn1.explicit(0, AlgorithmIdentifier))},
    {"keyEncryptionAlgorithm", AlgorithmIdentifier},
    {"encryptedKey", asn1.octet_string}
}

---@class OtherRecipientInfo
---@field type ObjectIdentifier
---@field value any

local OtherRecipientInfo = asn1.sequence {
    {"type", asn1.oid},
    {"value", asn1.any}
}

---@class RecipientInfo
---@field ktri KeyTransRecipientInfo|nil
---@field kari KeyAgreeRecipientInfo|nil
---@field kekri KEKRecipientInfo|nil
---@field pwri PasswordRecipientInfo|nil
---@field ori OtherRecipientInfo|nil

local RecipientInfo = asn1.choice {
    {"ktri", KeyTransRecipientInfo},
    {"kari", asn1.explicit(1, KeyAgreeRecipientInfo)},
    {"kekri", asn1.explicit(2, KEKRecipientInfo)},
    {"pwri", asn1.explicit(3, PasswordRecipientInfo)},
    {"ori", asn1.explicit(4, OtherRecipientInfo)}
}

---@class EncryptedContentInfo
---@field contentType ObjectIdentifier
---@field contentEncryptionAlgorithm AlgorithmIdentifier
---@field encryptedContent string|nil

local EncryptedContentInfo = asn1.sequence {
    {"contentType", asn1.oid},
    {"contentEncryptionAlgorithm", AlgorithmIdentifier},
    {"encryptedContent", asn1.optional(asn1.implicit(0, asn1.octet_string))}
}

---@class EnvelopedData
---@field version number
---@field originatorInfo OriginatorInfo|nil
---@field recipientInfos RecipientInfo[]
---@field encryptedContentInfo EncryptedContentInfo
---@field unprotectedAttrs Attribute[]|nil

local EnvelopedData = asn1.sequence {
    {"version", asn1.integer},
    {"originatorInfo", asn1.optional(asn1.implicit(0, OriginatorInfo))},
    {"recipientInfos", asn1.set_of(RecipientInfo)},
    {"encryptedContentInfo", EncryptedContentInfo},
    {"unprotectedAttrs", asn1.optional(asn1.explicit(1, asn1.set_of(Attribute)))}
}

--- Digested data

---@class DigestedData
---@field version number
---@field digestAlgorithm AlgorithmIdentifier
---@field encapContentInfo EncapsulatedContentInfo
---@field digest string

local DigestedData = asn1.sequence {
    {"version", asn1.integer},
    {"digestAlgorithm", AlgorithmIdentifier},
    {"encapContentInfo", EncapsulatedContentInfo},
    {"digest", asn1.octet_string}
}

--- Encrypted data

---@class EncryptedData
---@field version number
---@field encryptedContentInfo EncryptedContentInfo
---@field unprotectedAttrs Attribute[]|nil

local EncryptedData = asn1.sequence {
    {"version", asn1.integer},
    {"encryptedContentInfo", EncryptedContentInfo},
    {"unprotectedAttrs", asn1.optional(asn1.implicit(1, asn1.set_of(Attribute)))}
}

--- Authenticated data

---@class AuthenticatedData
---@field version number
---@field originatorInfo OriginatorInfo|nil
---@field recipientInfos RecipientInfo[]
---@field macAlgorithm AlgorithmIdentifier
---@field digestAlgorithm AlgorithmIdentifier|nil
---@field encapContentInfo EncapsulatedContentInfo
---@field authAttrs Attribute[]|nil
---@field mac string
---@field unauthAttrs Attribute[]|nil

local AuthenticatedData = asn1.sequence {
    {"version", asn1.integer},
    {"originatorInfo", asn1.optional(asn1.implicit(0, OriginatorInfo))},
    {"recipientInfos", asn1.set_of(RecipientInfo)},
    {"macAlgorithm", AlgorithmIdentifier},
    {"digestAlgorithm", asn1.optional(asn1.explicit(1, AlgorithmIdentifier))},
    {"encapContentInfo", EncapsulatedContentInfo},
    {"authAttrs", asn1.optional(asn1.implicit(2, asn1.set_of(Attribute)))},
    {"mac", asn1.octet_string},
    {"unauthAttrs", asn1.optional(asn1.implicit(3, asn1.set_of(Attribute)))}
}

--- Authenticated + encrypted data

---@class AuthEnvelopedData
---@field version number
---@field originatorInfo OriginatorInfo|nil
---@field recipientInfos RecipientInfo[]
---@field authEncryptedContentInfo EncryptedContentInfo
---@field authAttrs Attribute[]|nil
---@field mac string
---@field unauthAttrs Attribute[]|nil

local AuthEnvelopedData = asn1.sequence {
    {"version", asn1.integer},
    {"originatorInfo", asn1.optional(asn1.implicit(0, OriginatorInfo))},
    {"recipientInfos", asn1.set_of(RecipientInfo)},
    {"authEncryptedContentInfo", EncryptedContentInfo},
    {"authAttrs", asn1.optional(asn1.implicit(2, asn1.set_of(Attribute)))},
    {"mac", asn1.octet_string},
    {"unauthAttrs", asn1.optional(asn1.implicit(3, asn1.set_of(Attribute)))}
}

---@class ContentInfo
---@field type ObjectIdentifier

local ContentInfo = asn1.class {
    [container.pkcs7ContentTypeOIDs.data] = {{"content", asn1.explicit(0, asn1.octet_string)}},
    [container.pkcs7ContentTypeOIDs.signedData] = {{"content", asn1.explicit(0, SignedData)}},
    [container.pkcs7ContentTypeOIDs.envelopedData] = {{"content", asn1.explicit(0, EnvelopedData)}},
    [container.pkcs7ContentTypeOIDs.digestedData] = {{"content", asn1.explicit(0, DigestedData)}},
    [container.pkcs7ContentTypeOIDs.encryptedData] = {{"content", asn1.explicit(0, EncryptedData)}},
    [container.pkcs7ContentTypeOIDs.authData] = {{"content", asn1.explicit(0, AuthenticatedData)}},
    [container.pkcs7ContentTypeOIDs.authEnvelopedData] = {{"content", asn1.explicit(0, AuthEnvelopedData)}},
}

PKCS9AttributeList[container.pkcs9AttributeOIDs.pkcs7PDU] = {{"values", asn1.set {{"contentInfo", ContentInfo}}}}

---@class PKCS7Data: ContentInfo
---@field content string

---@class PKCS7SignedData: ContentInfo
---@field content SignedData

---@class PKCS7EnvelopedData: ContentInfo
---@field content EnvelopedData

---@class PKCS7DigestedData: ContentInfo
---@field content DigestedData

---@class PKCS7EncryptedData: ContentInfo
---@field content EncryptedData

---@class PKCS7AuthenticatedData: ContentInfo
---@field content AuthenticatedData

---@class PKCS7AuthenticatedEncryptedData: ContentInfo
---@field content AuthEnvelopedData

---@alias PKCS7 PKCS7Data|PKCS7SignedData|PKCS7EnvelopedData|PKCS7DigestedData|PKCS7EncryptedData|PKCS7AuthenticatedData|PKCS7AuthenticatedEncryptedData

-- PKCS#5 --

---@class PBKDF2_Params
---@field salt {specified: string|nil, otherSource: AlgorithmIdentifier|nil}
---@field iterationCount number
---@field keyLength number|nil
---@field prf AlgorithmIdentifier|nil

local PBKDF2_Params = asn1.sequence {
    {"salt", asn1.choice {
        {"specified", asn1.octet_string},
        {"otherSource", AlgorithmIdentifier}
    }},
    {"iterationCount", asn1.integer},
    {"keyLength", asn1.optional(asn1.integer)},
    {"prf", asn1.optional(AlgorithmIdentifier)}
}

---@class PBES2_Params
---@field keyDerivationFunc AlgorithmIdentifier
---@field encryptionScheme AlgorithmIdentifier

local PBES2_Params = asn1.sequence {
    {"keyDerivationFunc", AlgorithmIdentifier},
    {"encryptionScheme", AlgorithmIdentifier}
}

algorithm_list[container.keyDerivationAlgorithmOIDs.PBKDF2] = {{"pbkdf2Parameters", PBKDF2_Params}}
algorithm_list[container.passwordBasedEncryptionSchemeOIDs.PBES2] = {{"pbes2Parameters", PBES2_Params}}

-- End ASN.1 definitions --

--- Decodes a PEM file to DER data.
---@param data string The PEM to decode
---@return string der The DER data
---@return string type The type of the data as defined in the ASCII armor
function container.decodePEM(data)
    local type = data:match("^%-%-%-%-%-BEGIN ([^%-]+)")
    local retval = base64_decode(data:match("%-%-%-%-%-BEGIN [^%-]+%-%-%-%-%-\n(.+)\n%-%-%-%-%-END [^%-]+%-%-%-%-%-"):gsub("[^A-Za-z0-9/+=]", ""))
    return retval, type
end

--- Encodes DER data to PEM.
---@param data string The DER to encode
---@param type string The type of the PEM block
---@return string pem The PEM data
function container.encodePEM(data, type)
    return ([[-----BEGIN %s-----
%s
-----END %s-----
]]):format(type, base64_encode(data):gsub(("."):rep(64), "%0\n"), type)
end

--- Loads a PKCS#7 file from DER.
---@param data string The DER to load
---@return PKCS7 pk7 The loaded PKCS#7 structure
function container.loadPKCS7(data)
    local pk7 = ContentInfo.decode(data)
    return pk7
end

--- Loads a PKCS#8 file from DER.
---@param data string The DER to load
---@return PKCS8 pk8 The loaded PKCS#8 structure
function container.loadPKCS8(data)
    local pk8 = PrivateKeyInfo.decode(data)
    if pk8.privateKeyAlgorithm.type.string == container.publicKeyAlgorithmOIDs.ED25519 then
        pk8.privateKey = asn1.octet_string.decode(pk8.privateKey)
    end
    return pk8
end

--- Loads an encrypted PKCS#8 file from DER.
---@param data string The DER to load
---@return EncryptedPrivateKeyInfo pk8 The loaded encrypted PKCS#8 structure
function container.loadPKCS8Encrypted(data)
    return EncryptedPrivateKeyInfo.decode(data)
end

--- Loads a PKCS#10 CSR file from DER.
---@param data string The DER to load
---@return PKCS10 pk10 The loaded PKCS#10 structure
function container.loadPKCS10(data)
    return CertificationRequest.decode(data)
end

function container.loadPKCS12(data)

end

--- Loads a X.509 file from DER.
---@param data string The DER to load
---@return X509 cert The loaded X.509 structure
function container.loadX509(data)
    local cert = Certificate.decode(data) ---@type Certificate
    return cert
end

--- Loads a X.509 CRL file from DER.
---@param data string The DER to load
---@return X509CRL crl The loaded X.509 CRL structure
function container.loadX509CRL(data)
    local crl = CertificateList.decode(data) ---@type CertificateList
    return crl
end

--- Encodes a PKCS#7 structure to DER.
---@param pk7 PKCS7 The structure to encode
---@return string der The DER representation
function container.savePKCS7(pk7)
    return ContentInfo.encode(pk7)
end

--- Encodes a list of PKCS#7 attributes for use in a signature.
---@param attrs Attribute[] The attributes to encode
---@return string der The DER encoded form of the attributes
function container.encodePKCS7SignedAttrs(attrs)
    return asn1.set_of(Attribute).encode(attrs)
end

--- Encodes a PKCS#8 structure to DER.
---@param pk8 PKCS8 The structure to encode
---@return string der The DER representation
function container.savePKCS8(pk8)
    if (pk8.privateKeyAlgorithm.type.string or pk8.privateKeyAlgorithm.type) == container.publicKeyAlgorithmOIDs.ED25519 then
        return PrivateKeyInfo.encode {
            version = pk8.version,
            privateKeyAlgorithm = pk8.privateKeyAlgorithm,
            privateKey = asn1.octet_string.encode(pk8.privateKey),
            attributes = pk8.attributes
        }
    end
    return PrivateKeyInfo.encode(pk8)
end

--- Encodes an encrypted PKCS#8 structure to DER.
---@param pk8 EncryptedPrivateKeyInfo The structure to encode
---@return string der The DER representation
function container.savePKCS8Encrypted(pk8)
    return EncryptedPrivateKeyInfo.encode(pk8)
end

--- Encodes the inner info of a PKCS#10 CSR structure to DER, for use in signing.
---@param pk10 PKCS10 The structure to encode
---@return string der The DER representation of the inner info
function container.encodePKCS10InnerInfo(pk10)
    return CertificationRequestInfo.encode(pk10.toBeSigned)
end

--- Encodes a PKCS#10 CSR structure to DER.
---@param pk10 PKCS10 The structure to encode
---@return string der The DER representation
function container.savePKCS10(pk10)
    return CertificationRequest.encode(pk10)
end

function container.savePKCS12(pk12)

end

--- Encodes the X.509 certificate's to be signed contents to DER.
---@param cert X509 The structure to encode
---@return string der The DER representation of `toBeSigned`
function container.encodeX509InnerCertificate(cert)
    return TBSCertificate.encode(cert.toBeSigned)
end

--- Encodes a X.509 structure to DER.
---@param cert X509 The structure to encode
---@return string der The DER representation
function container.saveX509(cert)
    return Certificate.encode(cert)
end

--- Encodes the X.509 CRL's to be signed contents to DER.
---@param crl X509CRL The structure to encode
---@return string der The DER representation of `toBeSigned`
function container.encodeX509CRLInnerCertificate(crl)
    return CertificateListContent.encode(crl.toBeSigned)
end

--- Encodes a X.509 CRL structure to DER.
---@param crl X509CRL The structure to encode
---@return string der The DER representation
function container.saveX509CRL(crl)
    return CertificateList.encode(crl)
end

--- Prints an arbitrary object to the screen.
---@param cert table The table to print
---@param level? number The indentation level (defaults to 0)
function container.print(cert, level)
    level = level or 0
    for k, v in pairs(cert) do
        io.write(("  "):rep(level) .. (type(k) == "string" and k:gsub("%f[A-Z]([A-Z])", " %1"):gsub("^%w", string.upper) or k) .. ": ")
        if type(v) == "table" and type(v.type) ~= "string" then
            io.write("\n")
            container.print(v, level + 1)
        elseif type(v) == "table" then
            if v.type == "INTEGER" then
                --[[if #v.data == 0 then io.write("0\n") else
                    local digits = {};
                    for c in v.data:gmatch "." do
                        local carry = c:byte()
                        local i = 1
                        while i <= #digits or carry ~= 0 do
                            local value = (digits[i] or 0) * 256 + carry
                            carry = math.floor(value / 10)
                            value = value % 10
                            digits[i] = value
                            i = i + 1
                        end
                        while i > #digits do digits[#digits+1] = 0 end
                    end
                    io.write(table.concat(digits) .. "\n")
                end]]
                io.write(v.data:gsub(".", function(c) return ("%02X "):format(string.byte(c)) end) .. "\n")
            elseif v.type == "BIT STRING" then io.write(v.data:gsub(".", function(c) return ("%02X "):format(string.byte(c)) end) .. "\n")
            elseif v.type == "OBJECT IDENTIFIER" then
                io.write(v.string)
                for _, oids in pairs(container) do if type(oids) == "table" then
                    for l, w in pairs(oids) do if w == v.string then io.write(" (" .. l .. ")") break end end
                end end
                io.write("\n")
            elseif v.type == "UTCTime" then
                io.write(os.date("%c\n", os.time(v)))
            else io.write(" (" .. v.type .. ")\n") end
        elseif type(v) == "string" or type(v) == "number" then
            if string.match(v, "[^\32-\126]") then io.write(string.gsub(v, ".", function(c) return ("%02X "):format(string.byte(c)) end) .. "\n")
            else io.write(v .. "\n") end
        else io.write("\n") end
    end
end

return container
