local libcert = require "cert"
local secureboot = require "secureboot"
local ed25519 = require "ccryptolib.ed25519"

local keys = fs.find("/disk/secure-boot-*.key")
local id
if #keys == 0 then print("Please insert a disk with a secure boot key.")
elseif #keys == 1 then id = tonumber(keys[1]:match "secure%-boot%-(%d+)")
else
    local ids = {}
    for i, v in ipairs(keys) do ids[i] = v:match "secure%-boot%-(%d+)" end
    write("Multiple keys found for computer IDs: " .. table.concat(ids, ", ") .. "\nSelect an ID: ")
    repeat id = tonumber(read()) until id
end
local file = assert(fs.open("/disk/secure-boot-" .. id .. ".key", "rb"))
local pk8 = file.readAll()
file.close()
file = assert(fs.open("/disk/secure-boot-" .. id .. ".pem", "rb"))
local cert = file.readAll()
file.close()
local password
if pk8:match "ENCRYPTED PRIVATE KEY" then
    write("Password: ")
    password = read("\7")
end

if not fs.exists("/rom/pxboot/certs/enrolled/" .. id) then
    print("The computer is not currently enrolled in secure boot.")
	return
end
write("This will unenroll computer ID " .. id .. " from secure boot, revoking the key in the process. Are you sure you wish to continue? (y/N) ")
local response = read()
if response:lower() ~= "y" then return end

require "ccryptolib.random".initWithTiming()
local x509 = libcert.container.loadX509(libcert.container.decodePEM(cert))
local key, typ = libcert.container.decodePEM(pk8)
if typ == "ENCRYPTED PRIVATE KEY" then
	if not password then error("Private key is encrypted, but no password was provided", 2) end
	key = libcert.crypto.decryptKey(libcert.container.loadPKCS8Encrypted(key), password)
else key = libcert.container.loadPKCS8(key) end
local ok, err = secureboot.unenroll(cert, ed25519.sign(key.privateKey, x509.toBeSigned.subjectPublicKeyInfo.subjectPublicKey.data, tostring(id)))
if ok then
    fs.delete("/disk/secure-boot-" .. id .. ".key")
    fs.delete("/disk/secure-boot-" .. id .. ".pem")
    print("Successfully unenrolled computer ID " .. id .. " from secure boot. The now revoked key has been deleted. If you ran this program in order to revoke a leaked key, please restart the computer and run enroll-secure-boot again.")
else
    printError("Could not unenroll secure boot for computer ID " .. id .. ": " .. err)
end
