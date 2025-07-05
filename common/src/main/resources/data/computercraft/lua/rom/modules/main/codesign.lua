for i = 1, 1000 do
    local env = getfenv(i)
    if env.shell and env.require then
        _ENV = env
        break
    end
end

local ppath = package.path
package.path = "/rom/modules/main/?.lua;/rom/modules/main/?/init.lua"
local expect = require "cc.expect"
local container = require "cert.container"
local chain = require "cert.chain"
local signature = require "cert.signature"
package.path = ppath

--- Library to check code signatures from user code
--- @module codesign
local codesign = {}

--- Verifies the integrity of a file with a detached signature.
--- @param path string The path to the file to check
--- @return boolean ok Whether the file is signed and valid
--- @return string|nil err If failure, a reason why the check failed
local function verify(path)
	expect(1, path, "string")
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
    local cert = signature.getCertificate(pk7, 1)
    if not cert then return false, "Missing certificate" end
    return chain.validate(cert, pk7.content.certificates, "/rom/pxboot/certs")
end
codesign.verify = verify

--- A replacement for `shell.execute` which checks the signature of files.
--- This function cannot run ROM files for safety - if a ROM program is required, use normal `shell.execute`.
--- @param cmd string The command to run
--- @param ... string The arguments to pass to the command
--- @return boolean ok Whether the command succeeded
function codesign.execute(cmd, ...)
    local path = shell.resolveProgram(cmd)
    local ok, err = verify(path)
    if not ok then
        printError(err)
        return false
    end
    return shell.execute(path, ...)
end

--- A replacement for `loadfile` which checks the signature of files.
--- Modules in `/rom/modules` are assumed safe.
--- @param path string The path to load
--- @param mode string|nil The mode to load with
--- @param env table The environment to load in
--- @return function|nil fn The loaded function, or nil on failure
--- @return string|nil err If failed, an error describing the failure
function codesign.loadfile(path, mode, env)
	expect(1, path, "string")
    if not fs.combine(path):match "^/?rom/modules/" then
        local ok, err = verify(path)
        if not ok then return nil, err end
    end
    return loadfile(path, mode, env)
end

--- A replacement for `dofile` which checks the signature of files.
--- Modules in `/rom/modules` are assumed safe.
--- @param path string The path to load
--- @return ... any Any return values from the program
function codesign.dofile(path)
    expect(1, path, "string")
	if not fs.combine(path):match "^/?rom/modules/" then
		assert(verify(path))
	end
	return dofile(path)
end

--- Call this function to require all modules loaded with `require` to be signed.
--- Modules in `/rom/modules` are assumed safe.
function codesign.enforceModuleSigning()
	(package.loaders or package.searchers)[2] = function(name)
		local path, err = package.searchpath(name, package.path)
		if not path then return nil, err end
		if not fs.combine(path):match "^/?rom/modules/" then
			local ok, err = verify(path)
			if not ok then return nil, err end
		end
		local fn, err = loadfile(path, nil, _ENV)
		if fn then return fn, path
		else return nil, err end
	end
end

return codesign
