--[[
ASN.1 Framework for Lua
Copyright (c) 2015-2018 Kaarle Ritvanen
See LICENSE file for license details
--]]

local M = {}

---@class ASN1Coder
---@operator call(table): ASN1Coder
---@field decode fun(data: string): any
---@field encode fun(value: any): string
---@field extend fun(dec: fun(string): any, enc: fun(any): string): ASN1Coder
---@field _decode fun(data: string): any

---@param data string
---@return {tag: number, len: number, total_len: number}
---@return string
local function split(data)
    local meta = { tag = data:byte(), len = data:byte(2) }
    local ml = 2

    -- high tag numbers not supported
    assert(bit32.band(meta.tag, 0x1F) ~= 0x1F)

    if bit32.btest(meta.len, 0x80) then
        ml = 2 + bit32.band(meta.len, 0x7F)
        if ml < 3 then error('Invalid long length encoding') end

        meta.len = 0
        for _, b in ipairs { data:byte(3, ml) } do
            meta.len = bit32.bor(bit32.lshift(meta.len, 8), b)
        end
    end

    meta.total_len = ml + meta.len
    return meta, data:sub(ml + 1, -1)
end

local function check_type(v, t)
    local vt = type(v)
    if vt ~= t then error('Invalid value (' .. t .. ' expected, got ' .. vt .. ')') end
end

---@param decoder fun(data: string, params: table): any
---@param encoder fun(value: any, params: table): string
---@param params? table
---@return ASN1Coder
local function define(decoder, encoder, params)
    if not params then params = {} end

    local function decode(data) return decoder(data, params) end
    local function encode(value) return encoder(value, params) end

    return setmetatable(
        {
            _decode = decode,
            decode = function(data)
                local value = decode(data)
                --print(value)
                if value ~= nil then return value end
                if not params.optional then error('DER data does not conform to type definition') end
            end,
            encode = encode,
            extend = function(dec, enc)
                return define(
                    function(data) return dec(decode(data)) end,
                    function(value) return encode(enc(value)) end,
                    params
                )
            end,
            _params = params
        },
        {
            __call = function(t, p)
                if p then
                    if p.tag and not p.class then p.class = 'context' end
                    setmetatable(p, { __index = params })
                else
                    p = params
                end
                return define(decoder, encoder, p)
            end
        }
    )
end

---@param decoder fun(data: string, params: table): any
---@param encoder fun(value: any, params: table): string
---@return ASN1Coder
local function define_type(decoder, encoder)
    local function tag(params)
        -- high tag numbers not supported
        assert(params.tag < 0x1F)

        local res = bit32.bor(
            ({ universal = 0x00, context = 0x80 })[params.class], params.tag
        )
        if params.constructed then res = bit32.bor(res, 0x20) end
        return res
    end

    local function check_range(value, bounds)
        return (not bounds.min or value >= bounds.min) and
            (not bounds.max or value <= bounds.max)
    end

    local function check_size(value, params)
        return not params.size or check_range(#value, params.size)
    end

    return define(
        function(data, params)
            local meta, data = split(data)
            if #data ~= meta.len then
                error(
                    'Data length (' .. #data ..
                    ') does not match with the DER-encoded length (' .. meta.len ..
                    ')'
                )
                return
            end
            if params.tag ~= nil and meta.tag ~= tag(params) then return end

            local value = decoder(data, params)
            if check_size(value, params) and check_range(value, params) then
                return value
            end
        end,
        function(value, params)
            if params.value_type then check_type(value, params.value_type) end
            if not check_size(value, params) then
                error('Value to be encoded is of invalid length (' .. #value .. ')')
            end
            if not check_range(value, params) then
                error(
                    'Value to be encoded is outside the allowed range (' .. value .. ')'
                )
            end

            local data = encoder(value, params)
            local len = #data
            local enc_len = {}

            if len < 0x80 then
                enc_len[1] = len
            else
                while len > 0 do
                    table.insert(enc_len, 1, bit32.band(len, 0xFF))
                    len = bit32.rshift(len, 8)
                end
                table.insert(enc_len, 1, bit32.bor(0x80, #enc_len))
            end

            return string.char(tag(params), table.unpack(enc_len)) .. data
        end
    )
end

---@param tag number
---@return ASN1Coder
local function define_str(tag)
    local function identity(s) return s end
    return define_type(identity, identity) {
        class = 'universal', constructed = false, tag = tag, value_type = 'string'
    }
end

---@param decoder fun(data: string, params: table): any
---@param encoder fun(value: any, params: table): string
---@return ASN1Coder
local function define_seq(decoder, encoder)
    return define_type(decoder, encoder) {
        class = 'universal', constructed = true, tag = 0x10, value_type = 'table'
    }
end

---@param decoder fun(data: string, params: table): any
---@param encoder fun(value: any, params: table): string
---@return ASN1Coder
local function define_set(decoder, encoder)
    return define_type(decoder, encoder) {
        class = 'universal', constructed = true, tag = 0x11, value_type = 'table'
    }
end

---@param alts {[1]: string, [2]: ASN1Coder}[]
---@return ASN1Coder
function M.choice(alts)
    return define(
        function(data)
            for _, alt in ipairs(alts) do
                --print(alt[1])
                local value = alt[2]._decode(data)
                if value then return { [alt[1]] = value } end
            end
        end,
        function(value)
            local data
            for _, alt in ipairs(alts) do
                local v = value[alt[1]]
                if v then
                    if data then error('Ambiguous choice definition') end
                    data = alt[2].encode(v)
                end
            end
            if data then return data end
            error('Value to be encoded does not conform to any choice alternative')
        end
    )
end

---@param typ ASN1Coder
---@return ASN1Coder
function M.optional(typ)
    return define(
        function(data)
            return typ._decode(data)
        end,
        function(value)
            if value ~= nil then return typ.encode(value) end
            return ""
        end,
        {optional = true}
    )
end

---@param typ ASN1Coder
---@param val any
---@return ASN1Coder
function M.default(typ, val)
    return define(
        function(data)
            local value = typ._decode(data)
            if value == nil then value = val end
            return value
        end,
        function(value)
            if value ~= nil then return typ.encode(value) end
            return ""
        end,
        {optional = true}
    )
end

M.any = define(function(v) return v end, function(v) return v end)

M.null = define_type(function() return nil end, function() return "" end)
    { class = 'universal', constructed = false, tag = 0x05, value_type = 'nil', optional = true }

M.boolean = define_type(
    function(data) return string.byte(data) ~= 0x00 end,
    function(value) return string.char(value and 0xFF or 0x00) end
) { class = 'universal', constructed = false, tag = 0x01, value_type = 'boolean' }

local integer_mt = {__eq = function(a, b) return a.data == b.data end}
M.integer = define_type(
    function(data)
        if #data > 6 then
            return setmetatable({type = "INTEGER", data = data}, integer_mt)
        end

        local value = string.byte(data)

        -- negative integers not supported
        assert(bit32.band(value, 0x80) == 0x00)

        for _, b in ipairs { string.byte(data, 2, -1) } do
            value = value * 256 + b
        end
        return value
    end,
    function(value)
        if type(value) == "table" and value.type == "INTEGER" then
            return value.data
        end

        check_type(value, "number")

        if value ~= math.floor(value) then
            error('Not an integer: ' .. value)
        end

        -- negative integers not supported
        assert(value > -1)

        local octs = {}
        while value > 0 do
            table.insert(octs, 1, value % 256)
            value = math.floor(value / 256)
        end
        if #octs == 0 then octs[1] = 0 end
        if bit32.band(octs[1], 0x80) == 0x80 then table.insert(octs, 1, 0) end
        return string.char(table.unpack(octs))
    end
) { class = 'universal', constructed = false, tag = 0x02 }

M.bit_string = define_type(
    function(data, params)
        local unused = data:byte()
        if unused > 7 then error('Invalid DER encoding for unused bits') end

        if not params.enum then return {type = "BIT STRING", data = data:sub(2), unused = unused} end

        local value = ''
        while #data > 1 do
            data = data:sub(2, -1)
            local oct = data:byte()
            for i = 7, #data == 1 and unused or 0, -1 do
                local mask = bit32.lshift(i, 1)
                value = value .. (bit32.band(oct, mask) == mask and '1' or '0')
            end
        end

        local m = {}
        for i = 1, #value do m[params.enum[i]] = value:sub(i, i) == '1' end
        return m
    end,
    function(value, params)
        if params.enum then
            check_type(value, 'table')
            local s = ''
            for _, k in ipairs(params.enum) do
                s = s .. (value[k] and '1' or '0')
            end
            value = s

            local octs = {}
            local unused = 0
            while value > '' do
                local oct = 0
                unused = 8
                while value > '' and unused > 0 do
                    unused = unused - 1
                    oct = bit32.bor(
                        oct, bit32.lshift(tonumber(value:sub(1, 1), 2), unused)
                    )
                    value = value:sub(2, -1)
                end
                table.insert(octs, oct)
            end
            table.insert(octs, 1, unused)
            return string.char(table.unpack(octs))
        else
            check_type(value, 'table')

            return string.char(value.unused) .. value.data
        end
    end
) { class = 'universal', constructed = false, tag = 0x03 }

M.octet_string = define_str(0x04)

M.ia5string = define_str(0x16)

M.printable_string = define_str(0x13)
M.teletex_string = define_str(0x15)
M.bmp_string = define_str(0x1E)
M.universal_string = define_str(0x1C)

M.utf8string = define_type(
    function(data)
        local str = ""
        for _, c in utf8.codes(data) do
            if c < 256 then str = str .. string.char(c)
            else str = str .. "\x1A" end
        end
        return str
    end,
    function(value)
        check_type(value, "string")
        return utf8.char(value:byte(1, -1))
    end
) { class = 'universal', constructed = false, tag = 0x0C }

M.oid = define_type(
    function(data, params)
        local n = data:byte()
        local retval = {type = "OBJECT IDENTIFIER", math.floor(n / 40), n % 40}
        local pos = 2
        while pos <= #data do
            local c = data:byte(pos)
            pos = pos + 1
            n = bit32.band(c, 0x7F)
            while bit32.btest(c, 0x80) do
                c = data:byte(pos)
                pos = pos + 1
                n = bit32.lshift(n, 7) + bit32.band(c, 0x7F)
            end
            retval[#retval+1] = n
        end
        retval.string = table.concat(retval, ".")
        return retval
    end, function(value, params)
        if type(value) == "string" then
            local t = {}
            for n in value:gmatch "%d+" do t[#t+1] = tonumber(n) end
            value = t
        end
        check_type(value, "table")
        local str = string.char(value[1] * 40 + value[2])
        for i = 3, #value do
            local n = value[i]
            if n > 0x7F then
                local octs = {}
                while n > 0x7F do
                    table.insert(octs, 1, bit32.band(n, 0x7F) + 0x80)
                    n = bit32.rshift(n, 7)
                end
                table.insert(octs, 1, n + 0x80)
                octs[#octs] = bit32.band(octs[#octs], 0x7F)
                str = str .. string.char(table.unpack(octs))
            else str = str .. string.char(n) end
        end
        return str
    end
) { class = 'universal', constructed = false, tag = 0x06 }

M.utc_time = define_type(
    function(data, params)
        local y, M, d, h, m, s, tz = data:match("(%d%d)(%d%d)(%d%d)(%d%d)(%d%d)(%d?%d?)Z?([%+%-]?%d*)")
        y, M, d = tonumber(y), tonumber(M), tonumber(d)
        h, m, s = tonumber(h), tonumber(m), tonumber(s) or 0
        if #tz > 0 then
            local sign = tz:sub(1, 1) == "+" and 1 or -1
            tz = tonumber(tz:sub(2))
            tz = ((tz % 100) + (math.floor(tz / 100) * 60)) * sign
        else tz = 0 end
        return {type = "UTCTime", year = y + (y >= 50 and 1900 or 2000), month = M, day = d, hour = h, min = m, sec = s, offset = 0}
    end,
    function(value, params)
        return ("%02d%02d%02d%02d%02d%02dZ"):format(value.year % 100, value.month, value.day, value.hour, value.min, value.sec or 0)
    end
) { class = 'universal', constructed = false, tag = 0x17 }

M.generalized_time = define_type(
    function(data, params)
        local y, M, d, h, m, s, tz = data:match("(%d%d%d%d)(%d%d)(%d%d)(%d%d)(%d%d)(%d?%d?)Z?([%+%-]?%d*)")
        y, M, d = tonumber(y), tonumber(M), tonumber(d)
        h, m, s = tonumber(h), tonumber(m), tonumber(s) or 0
        if #tz > 0 then
            local sign = tz:sub(1, 1) == "+" and 1 or -1
            tz = tonumber(tz:sub(2))
            tz = ((tz % 100) + (math.floor(tz / 100) * 60)) * sign
        else tz = 0 end
        return {type = "GeneralizedTime", year = y, month = M, day = d, hour = h, min = m, sec = s, offset = tz}
    end,
    function(value, params)
        return ("%04d%02d%02d%02d%02d%02dZ"):format(value.year, value.month, value.day, value.hour, value.min, value.sec or 0, value.offset)
    end
) { class = 'universal', constructed = false, tag = 0x18 }

---@param tag number
---@param syntax ASN1Coder
---@return ASN1Coder
function M.explicit(tag, syntax)
    return define_type(
        function(data) return syntax.decode(data) end,
        function(value) return syntax.encode(value) end
    ) { class = 'context', constructed = true, tag = tag }
end

---@param tag number
---@param syntax ASN1Coder
---@return ASN1Coder
function M.implicit(tag, syntax)
    return syntax { class = 'context', tag = tag }
end

---@param comps {[1]: string, [2]: ASN1Coder}[]
---@return ASN1Coder
function M.sequence(comps)
    return define_seq(
        function(data)
            local value = {}
            for _, comp in ipairs(comps) do
                --print(comp[1], #data)
                if #data == 0 then
                    if not comp[2]._params.optional then error("Incomplete sequence") end
                else
                    local meta = split(data)
                    local v
                    if comp[2] == M.any then v = data:sub(1, meta.total_len)
                    else v = comp[2].decode(data:sub(1, meta.total_len)) end
                    --print(v)
                    value[comp[1]] = v
                    if v ~= nil then data = data:sub(meta.total_len + 1, -1) end
                end
            end
            if #data > 0 then
                error('Excess data after a DER-encoded sequence')
            end
            return value
        end,
        function(value)
            local data = ''
            for _, comp in ipairs(comps) do
                --print(comp[1])
                if comp[2] == M.any then data = data .. value[comp[1]]
                else data = data .. comp[2].encode(value[comp[1]]) end
            end
            return data
        end
    )
end

---@param comps ASN1Coder
---@return ASN1Coder
function M.sequence_of(comps)
    return define_seq(
        function(data)
            local value = {}
            while #data > 0 do
                local meta = split(data)
                table.insert(value, comps.decode(data:sub(1, meta.total_len)))
                data = data:sub(meta.total_len + 1, -1)
            end
            return value
        end,
        function(value)
            local data = ''
            for _, comp in ipairs(value) do data = data .. comps.encode(comp) end
            return data
        end
    )
end

---@param comps {[1]: string, [2]: ASN1Coder}[]
---@return ASN1Coder
function M.set(comps)
    return define_set(
        function(data)
            local value = {}
            for _, comp in ipairs(comps) do
                --print(comp[1])
                local meta = split(data)
                local v
                if comp[2] == M.any then v = data:sub(1, meta.total_len)
                else v = comp[2].decode(data:sub(1, meta.total_len)) end
                value[comp[1]] = v
                if v ~= nil then data = data:sub(meta.total_len + 1, -1) end
            end
            if #data > 0 then
                error('Excess data after a DER-encoded sequence')
            end
            return value
        end,
        function(value)
            local data = ''
            for _, comp in ipairs(comps) do
                if comp[2] == M.any then data = data .. value[comp[1]]
                else data = data .. comp[2].encode(value[comp[1]]) end
            end
            return data
        end
    )
end

---@param comps ASN1Coder
---@return ASN1Coder
function M.set_of(comps)
    return define_set(
        function(data)
            local value = {}
            while #data > 0 do
                local meta = split(data)
                table.insert(value, comps.decode(data:sub(1, meta.total_len)))
                data = data:sub(meta.total_len + 1, -1)
            end
            return value
        end,
        function(value)
            local enc = {}
            for _, comp in ipairs(value) do enc[#enc+1] = comps.encode(comp) end
            table.sort(enc)
            return table.concat(enc)
        end
    )
end

---@param comps {[string]: {[1]: string, [2]: ASN1Coder}[]}
---@return ASN1Coder
function M.class(comps)
    return define_seq(
        function(data)
            local value = {}
            do
                local meta = split(data)
                value.type = M.oid.decode(data:sub(1, meta.total_len))
                data = data:sub(meta.total_len + 1, -1)
            end
            --print(value.type.string)
            local typ = comps[value.type.string]
            if typ == nil then error("Unknown type for class") end
            for _, comp in ipairs(typ) do
                --print(comp[1], #data)
                if #data == 0 then
                    if not comp[2]._params.optional then error("Incomplete sequence") end
                else
                    local meta = split(data)
                    if comp[2] == M.any then value[comp[1]] = data:sub(1, meta.total_len)
                    else value[comp[1]] = comp[2].decode(data:sub(1, meta.total_len)) end
                    data = data:sub(meta.total_len + 1, -1)
                end
            end
            if data > '' then
                error('Excess data after a DER-encoded sequence')
            end
            return value
        end,
        function(value)
            local data = M.oid.encode(value.type)
            local str = type(value.type) == "string" and value.type or value.type.string
            local typ = comps[str]
            if typ == nil then error("Unknown type for class") end
            for _, comp in ipairs(typ) do
                --print(comp[1])
                if comp[2] == M.any then data = data .. value[comp[1]]
                else data = data .. comp[2].encode(value[comp[1]]) end
            end
            return data
        end
    )
end

return M
