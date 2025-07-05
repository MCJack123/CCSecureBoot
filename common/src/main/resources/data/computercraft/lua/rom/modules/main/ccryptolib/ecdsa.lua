--- The ECDSA digital signature scheme, using Curve25519 + SHA-512.

local expect = require "cc.expect".expect
local lassert = require "ccryptolib.internal.util".lassert
local fq     = require "ccryptolib.internal.fq"
local sha512 = require "ccryptolib.internal.sha512"
local c25    = require "ccryptolib.internal.curve25519"
local util   = require "ccryptolib.internal.util"
local random = require "ccryptolib.random"

--- Computes a public key from a secret key.
--- @param sk string A random 32-byte secret key.
--- @return string pk The matching 32-byte public key.
local function publicKey(sk)
    expect(1, sk, "string")
    assert(#sk == 32, "secret key length must be 32")

    return c25.encode(c25.scale(c25.mulG(util.bits(sk))))
end

--- Signs a message.
--- @param sk string The signer's secret key.
--- @param pk string The signer's public key.
--- @param msg string The message to be signed.
--- @return string sig The 64-byte signature on the message.
local function sign(sk, pk, msg)
    expect(1, sk, "string")
    lassert(#sk == 32, "secret key length must be 32", 2)
    expect(2, pk, "string")
    lassert(#pk == 32, "public key length must be 32", 2)
    expect(3, msg, "string")

    
end

--- Verifies a signature on a message.
--- @param pk string The signer's public key.
--- @param msg string The signed message.
--- @param sig string The alleged signature.
--- @return boolean valid Whether the signature is valid or not.
local function verify(pk, msg, sig)
    expect(1, pk, "string")
    lassert(#pk == 32, "public key length must be 32", 2) --- @cast pk String32
    expect(2, msg, "string")
    expect(3, sig, "string")
    lassert(#sig == 64, "signature length must be 64", 2)

    local y = ed.decode(pk)
    if not y then return false end

    local rStr = sig:sub(1, 32)
    local sStr = sig:sub(33)

    local e = fq.decodeWide(sha512.digest(rStr .. pk .. msg))

    local gs = ed.mulG(fq.bits(fq.decode(sStr)))
    local ye = ed.mul(y, fq.bits(e))
    local rv = ed.sub(gs, ed.niels(ye))

    return ed.encode(rv) == rStr
end

return {
    publicKey = publicKey,
    sign = sign,
    verify = verify,
}
