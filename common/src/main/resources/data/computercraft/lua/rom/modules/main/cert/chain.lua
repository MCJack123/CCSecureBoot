local expect = require "cc.expect"
local ed25519 = require "ccryptolib.ed25519"
local container = require "cert.container"
local util = require "cert.util"

local chain = {}

---@param cert X509
---@param certList X509[]
---@param roots X509[]
---@param revoked ({type: "INTEGER", data: string}|number)[]
---@return boolean trusted
---@return string|nil reason
local function chain_validate_internal(cert, certList, roots, revoked)
    -- Check that the certificate isn't revoked
	for _, v in ipairs(revoked) do
	    if cert.toBeSigned.serialNumber == v or (type(cert.toBeSigned.serialNumber) == "table" and type(v) == "table" and cert.toBeSigned.serialNumber.data == v.data) then
	        return false, "Certificate was revoked"
	    end
	end
    -- Find the issuing certificate
    local parent, isRoot
    for _, v in ipairs(certList) do
        if util.compareNames(v.toBeSigned.subject, cert.toBeSigned.issuer) then parent, isRoot = v, false end
    end
    for _, v in ipairs(roots) do
        if util.compareNames(v.toBeSigned.subject, cert.toBeSigned.issuer) then parent, isRoot = v, true end
    end
    if not parent then return false, "Could not find path to root" end -- No known parent
    -- Verify the signature of the certificate
    local der = container.encodeX509InnerCertificate(cert)
    if parent.toBeSigned.subjectPublicKeyInfo.algorithm.type.string ~= container.signatureAlgorithmOIDs.ED25519 then
        return false, "Certificate has unsupported signature type"
    end
    if not ed25519.verify(parent.toBeSigned.subjectPublicKeyInfo.subjectPublicKey.data, der, cert.signature.data) then
        return false, "Could not verify signature of certificate"
    end
    -- If this is a root certificate, we made it
    if isRoot then return true end
    -- Otherwise, make sure this isn't self-signed so we don't end up in an infinite loop
    if util.compareNames(cert.toBeSigned.subject, cert.toBeSigned.issuer) then return false, "Chain certificate is self-signed" end
    -- Continue validating with the parent
    return chain_validate_internal(parent, certList, roots, revoked)
end

--- Validates a certificate up to a root of trust.
---@param cert X509 The certificate to start at
---@param certList? X509[] Additional certificates that may be in the chain of trust
---@param rootPath? string The path to the root certificate store (defaults to "/etc/certs")
---@param additionalRoots? X509[] Additional root certificates to trust
---@return boolean trusted Whether the certificate can be trusted
---@return string|nil reason If not trusted, a reason why the certificate failed to validate
function chain.validate(cert, certList, rootPath, additionalRoots)
    expect(1, cert, "table")
    expect(2, certList, "table", "nil")
    rootPath = expect(3, rootPath, "string", "nil") or "/etc/certs"
    expect(4, additionalRoots, "table", "nil")
    local roots, revoked = {}, {}
    if additionalRoots then
        for _, v in ipairs(additionalRoots) do roots[#roots+1] = v end
    end
    if rootPath ~= "" and fs.isDir(rootPath) then
        for _, p in ipairs(fs.list(rootPath)) do
            if not fs.isDir(fs.combine(rootPath, p)) then
                local file = io.open(fs.combine(rootPath, p), "rb")
                if file then
                    local data = file:read("*a")
                    file:close()
                    local type = "CERTIFICATE"
                    if data:match("^%-%-%-%-%-BEGIN") then data, type = container.decodePEM(data) end
                    if type == "CERTIFICATE" then
						local ok, c = pcall(container.loadX509, data)
						if ok then roots[#roots+1] = c end
					elseif type == "X509 CRL" then
                        local ok, c = pcall(container.loadX509CRL, data)
						if ok and c.toBeSigned.revokedCertificates then
                            -- TODO: verify signature of CRL
							for _, v in ipairs(c.toBeSigned.revokedCertificates) do
								revoked[#revoked+1] = v.serialNumber
							end
						end
					end
                end
            end
        end
    end
    return chain_validate_internal(cert, certList or {}, roots, revoked)
end

return chain
