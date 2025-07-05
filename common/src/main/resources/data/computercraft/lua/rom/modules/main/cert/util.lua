local util = {}

local band    = bit32.band
local bxor    = bit32.bxor
local brshift = bit32.rshift
local upack   = unpack or table.unpack

---@param name Name
---@return table<string, string>
function util.reduceName(name)
    local retval = {}
    for _, v in ipairs(name.rdnSequence) do
        local s = v[1].value
        if type(s) == "table" then s = select(2, next(s)) end
        retval[v[1].type.string] = s
    end
    return retval
end

---@param a Name
---@param b Name
---@return boolean ok
function util.compareNames(a, b)
    local an = util.reduceName(a)
    local bn = util.reduceName(b)
    for k, v in pairs(an) do if bn[k] ~= v then return false end end
    for k, v in pairs(bn) do if an[k] ~= v then return false end end
    return true
end

-- From https://pastebin.com/6UV4qfNF - MIT

--- PBKDF2 key derivation
---@param hmac fun(data: number[], key: string): number[]
---@param hashlen number
---@param pass string
---@param salt string|number[]
---@param iter number
---@param dklen? number
---@return string
function util.pbkdf2(hmac, hashlen, pass, salt, iter, dklen)
    salt = type(salt) == "table" and salt or {tostring(salt):byte(1,-1)}
    dklen = dklen or 32
    local block = 1
    local out = {}

    while dklen > 0 do
        local ikey = {}
        local isalt = {upack(salt)}
        local clen = dklen > hashlen and hashlen or dklen

        isalt[#isalt+1] = band(brshift(block, 24), 0xFF)
        isalt[#isalt+1] = band(brshift(block, 16), 0xFF)
        isalt[#isalt+1] = band(brshift(block, 8), 0xFF)
        isalt[#isalt+1] = band(block, 0xFF)

        for j = 1, iter do
            isalt = hmac(isalt, pass)
            for k = 1, clen do ikey[k] = bxor(isalt[k], ikey[k] or 0) end
        end
        dklen = dklen - clen
        block = block+1
        for k = 1, clen do out[#out+1] = ikey[k] end
    end

    return string.char(upack(out))
end

---@param data number[]
---@param blocksize number
---@return number[] data
function util.pkcs7pad(data, blocksize)
    local left = blocksize - (#data % blocksize)
    for _ = 1, left do data[#data+1] = left end
    return data
end

---@param data number[]
---@return number[] data
function util.pkcs7unpad(data)
    local left = data[#data]
    for _ = 1, left do data[#data] = nil end
    return data
end

return util
