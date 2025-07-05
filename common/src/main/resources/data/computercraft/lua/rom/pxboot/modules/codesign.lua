-- Requires ccryptolib, sha2, asn1 and libcert installed to rom/modules/main
local container = require "cert.container"
local chain = require "cert.chain"
local signature = require "cert.signature"
local args, modpath = ...
args = args or {}
local dir = fs.getDir(fs.getDir(modpath))

local function verify(path)
    local sig = path .. ".pk7"
    if not fs.exists(sig) then sig = path .. ".pem" end
    if not fs.exists(sig) then sig = path .. ".sig" end
    if not fs.exists(sig) then return false, "Could not find signature file" end
    local file, err = fs.open(path, "rb")
    if not file then return false, err end
    local data = file.readAll()
    file.close()
    file, err = fs.open(sig, "rb")
    if not file then return false, err end
    local sigdata = file.readAll()
    file.close()
    if sigdata:match "^%-%-%-%-%-BEGIN ([^%-]+)" then sigdata = container.decodePEM(sigdata) end
    local pk7 = container.loadPKCS7(sigdata)
    local ok, err = signature.verify(pk7, data)
    if not ok then return false, err end
    return chain.validate(signature.getCertificate(pk7, 1), pk7.content.certificates, fs.combine(dir, "certs"))
end

local function assert(ok, err) if not ok then error(err, 0) end end

local old_kernel, old_chainloader, old_insmod, old_include = cmds.kernel, cmds.chainloader, cmds.insmod, config.include
if not args.allowCraftOS then cmds.craftos = nil end

function cmds.kernel(t)
    assert(verify(t.path))
    return old_kernel(t)
end

function cmds.chainloader(t)
    assert(verify(t.path))
    return old_chainloader(t)
end

function cmds.insmod(t)
    local path
    if t.name:match "^/" then path = t.name
    elseif t.name:find "[/%.]" then path = fs.combine(shell and fs.getDir(shell.getRunningProgram()) or "pxboot", t.name)
    else path = fs.combine(shell and fs.getDir(shell.getRunningProgram()) or "pxboot", "modules/" .. t.name .. ".lua") end
    assert(verify(path))
    return old_insmod(t)
end

local runningDir
function config.include(path)
	if not path:match "^/" then path = fs.combine(runningDir, path) end
    for _, v in ipairs(fs.find(path)) do
        repeat
            local ok, err = verify(v)
            if not ok then
                printError("Could not verify config file: " .. err)
                print("Press any key to continue...")
                os.pullEvent("key")
                break
            end
            local fn, err = loadfile(v, "t", getfenv(2))
            if not fn then
                printError("Could not load config file: " .. err)
                print("Press any key to continue...")
                os.pullEvent("key")
                break
            end
            local old = runningDir
            runningDir = fs.getDir(v)
            local ok, err = pcall(fn)
            runningDir = old
            if not ok then
                printError("Failed to execute config file: " .. err)
                print("Press any key to continue...")
                os.pullEvent("key")
                break
            end
        until true
    end
end
for i = 1, 10 do
    local k = debug.getupvalue(old_include, i)
    if k == "runningDir" then
        for j = 1, 10 do
            k = debug.getupvalue(config.include, j)
            if k == "runningDir" then
                debug.upvaluejoin(config.include, j, old_include, i)
                break
            end
        end
        break
    end
end
