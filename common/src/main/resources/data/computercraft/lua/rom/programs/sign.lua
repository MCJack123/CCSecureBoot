local libcert = require "cert"

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

local path = shell.resolve(assert(..., "Usage: sign <file.lua>"))
file = assert(fs.open(path, "rb"))
local data = file.readAll()
file.close()
require "ccryptolib.random".initWithTiming()
local sig = libcert.sign(cert, pk8, data, nil, password)
file = assert(fs.open(path .. ".sig", "wb"))
file.write(sig)
file.close()
