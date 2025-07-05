if not (fs or term or os.pullEvent) then error("This program must be run from CraftOS.") end

local expect = require "cc.expect"
if not getmetatable(expect) then setmetatable(expect, {__call = function(self, ...) return self.expect(...) end})
elseif not getmetatable(expect).__call then getmetatable(expect).__call = function(self, ...) return self.expect(...) end end

local entries = {}
local entry_names = {}
local bootcfg = {}
local cmds = {}
local userGlobals = {}
local monitor
local config

local function unbios(path, ...)
    -- UnBIOS by JackMacWindows
    -- This will undo most of the changes/additions made in the BIOS, but some things may remain wrapped if `debug` is unavailable
    -- To use, just place a `bios.lua` in the root of the drive, and run this program
    -- Here's a list of things that are irreversibly changed:
    -- * both `bit` and `bit32` are kept for compatibility
    -- * string metatable blocking (on old versions of CC)
    -- In addition, if `debug` is not available these things are also irreversibly changed:
    -- * old Lua 5.1 `load` function (for loading from a function)
    -- * `loadstring` prefixing (before CC:T 1.96.0)
    -- * `http.request`
    -- * `os.shutdown` and `os.reboot`
    -- * `peripheral`
    -- * `turtle.equip[Left|Right]`
    -- Licensed under the MIT license
    local old_dofile = _G.dofile
    local kernelArgs = table.pack(...)
    local keptAPIs = {bit32 = true, bit = true, ccemux = true, config = true, coroutine = true, debug = true, ffi = true, fs = true, http = true, io = true, jit = true, mounter = true, os = true, periphemu = true, peripheral = true, redstone = true, rs = true, term = true, utf8 = true, _HOST = true, _CC_DEFAULT_SETTINGS = true, _CC_DISABLE_LUA51_FEATURES = true, _VERSION = true, assert = true, collectgarbage = true, error = true, gcinfo = true, getfenv = true, getmetatable = true, ipairs = true, load = true, loadstring = true, math = true, newproxy = true, next = true, pairs = true, pcall = true, rawequal = true, rawget = true, rawlen = true, rawset = true, select = true, setfenv = true, setmetatable = true, string = true, table = true, tonumber = true, tostring = true, type = true, unpack = true, xpcall = true, turtle = true, pocket = true, commands = true, _G = true, sound = true}
    local t = {}
    for k in pairs(_G) do if not keptAPIs[k] and not userGlobals[k] then table.insert(t, k) end end
    for _,k in ipairs(t) do _G[k] = nil end
    local native = monitor or _G.term.native()
    for _, method in ipairs { "nativePaletteColor", "nativePaletteColour", "screenshot" } do
        native[method] = _G.term[method]
    end
    _G.term = native
    _G.http.checkURL = _G.http.checkURLAsync
    _G.http.websocket = _G.http.websocketAsync
    if _G.commands then _G.commands = _G.commands.native end
    if _G.turtle then _G.turtle.native, _G.turtle.craft = nil end
    local delete = {os = {"version", "pullEventRaw", "pullEvent", "run", "loadAPI", "unloadAPI", "sleep"}, http = {"get", "post", "put", "delete", "patch", "options", "head", "trace", "listen", "checkURLAsync", "websocketAsync"}, fs = {"complete", "isDriveRoot"}}
    for k,v in pairs(delete) do for _,a in ipairs(v) do _G[k][a] = nil end end
    -- Set up TLCO
    -- This functions by crashing `rednet.run` by removing `os.pullEventRaw`. Normally
    -- this would cause `parallel` to throw an error, but we replace `error` with an
    -- empty placeholder to let it continue and return without throwing. This results
    -- in the `pcall` returning successfully, preventing the error-displaying code
    -- from running - essentially making it so that `os.shutdown` is called immediately
    -- after the new BIOS exits.
    --
    -- From there, the setup code is placed in `term.native` since it's the first
    -- thing called after `parallel` exits. This loads the new BIOS and prepares it
    -- for execution. Finally, it overwrites `os.shutdown` with the new function to
    -- allow it to be the last function called in the original BIOS, and returns.
    -- From there execution continues, calling the `term.redirect` dummy, skipping
    -- over the error-handling code (since `pcall` returned ok), and calling
    -- `os.shutdown()`. The real `os.shutdown` is re-added, and the new BIOS is tail
    -- called, which effectively makes it run as the main chunk.
    local olderror = error
    _G.error = function() end
    _G.term.redirect = function() end
    function _G.term.native()
        _G.term.native = nil
        _G.term.redirect = nil
        _G.error = olderror
        term.setBackgroundColor(32768)
        term.setTextColor(1)
        term.setCursorPos(1, 1)
        term.setCursorBlink(true)
        term.clear()
        local fn
        if type(path) == "function" then
            fn = path
        else
            local file = fs.open(path, "r")
            if file == nil then
                term.setCursorBlink(false)
                term.setTextColor(16384)
                term.write("Could not find kernel. pxboot cannot continue.")
                term.setCursorPos(1, 2)
                term.write("Press any key to continue")
                coroutine.yield("key")
                os.shutdown()
            end
            local err
            fn, err = loadstring(file.readAll(), "=kernel")
            file.close()
            if fn == nil then
                term.setCursorBlink(false)
                term.setTextColor(16384)
                term.write("Could not load kernel. pxboot cannot continue.")
                term.setCursorPos(1, 2)
                term.write(err)
                term.setCursorPos(1, 3)
                term.write("Press any key to continue")
                coroutine.yield("key")
                os.shutdown()
            end
        end
        setfenv(fn, _G)
        local oldshutdown = os.shutdown
        os.shutdown = function()
            os.shutdown = oldshutdown
            return fn(table.unpack(kernelArgs, 1, kernelArgs.n))
        end
    end
    if debug then
        -- Restore functions that were overwritten in the BIOS
        -- Apparently this has to be done *after* redefining term.native
        local function restoreValue(tab, idx, name, hint)
            local i, key, value = 1, debug.getupvalue(tab[idx], hint)
            while key ~= name and not (key == nil and i > 1) do
                key, value = debug.getupvalue(tab[idx], i)
                i=i+1
            end
            tab[idx] = value or tab[idx]
        end
        restoreValue(_G, "loadstring", "nativeloadstring", 1)
        restoreValue(_G, "load", "nativeload", 5)
        restoreValue(http, "request", "nativeHTTPRequest", 3)
        restoreValue(os, "shutdown", "nativeShutdown", 1)
        restoreValue(os, "reboot", "nativeReboot", 1)
        if turtle then
            restoreValue(turtle, "equipLeft", "v", 1)
            restoreValue(turtle, "equipRight", "v", 1)
        end
        do
            local i, key, value = 1, debug.getupvalue(peripheral.isPresent, 2)
            while key ~= "native" and key ~= nil do
                key, value = debug.getupvalue(peripheral.isPresent, i)
                i=i+1
            end
            _G.peripheral = value or peripheral
        end
        -- Restore Discord plugin in CraftOS-PC
        if debug.getupvalue(old_dofile, 2) == "status" then
            local _, status = debug.getupvalue(old_dofile, 2)
            _, _G.discord = debug.getupvalue(status, 4)
        end
    end
    coroutine.yield()
end

function cmds.kernel(t)
    bootcfg.fn = unbios
    bootcfg.args = {t.path}
end

function cmds.chainloader(t)
    bootcfg.fn = shell and shell.run or function(path, ...) os.run({}, path, ...) end
    bootcfg.args = {t.path}
end

function cmds.craftos(t)
    bootcfg.fn = function()
        term.setTextColor(colors.yellow)
        print(os.version())
        term.setTextColor(colors.white)
        if settings.get("motd.enable") then
            if shell then shell.run("motd")
            else os.run({}, "/rom/programs/motd.lua") end
        end
    end
    bootcfg.args = {}
end

function cmds.args(t)
    if not bootcfg.args then error("config.lua:" .. t.line .. ": args command must come after boot type", 0) end
    for i = 1, #t.args do bootcfg.args[#bootcfg.args+1] = t.args[i] end
end

function cmds.global(t)
    _G[t.key] = t.value
    userGlobals[t.key] = true
end

function cmds.monitor(t)
    if peripheral.hasType then assert(peripheral.hasType(t.name, "monitor"), "peripheral '" .. t.name .. "' does not exist or is not a monitor")
    else assert(peripheral.getType(t.name) == "monitor", "peripheral '" .. t.name .. "' does not exist or is not a monitor") end
    monitor = peripheral.wrap(t.name)
    term.redirect(monitor)
end

function cmds.insmod(t)
    local path
    if t.name:match "^/" then path = t.name
    elseif t.name:find "[/%.]" then path = fs.combine(shell and fs.getDir(shell.getRunningProgram()) or "pxboot", t.name)
    else path = fs.combine(shell and fs.getDir(shell.getRunningProgram()) or "pxboot", "modules/" .. t.name .. ".lua") end
    assert(loadfile(path, nil, setmetatable({entries = entries, bootcfg = bootcfg, cmds = cmds, userGlobals = userGlobals, unbios = unbios, config = config}, {__index = _ENV})))(t.args, path)
end

local function boot(entry)
    term.setBackgroundColor(colors.black)
    term.setTextColor(colors.white)
    term.clear()
    term.setCursorPos(1, 1)
    for i = 0, 15 do term.setPaletteColor(2^i, term.nativePaletteColor(2^i)) end
    for _, v in ipairs(entry.commands) do
        local ok, err
        if type(v) == "function" then ok, err = pcall(v)
        else ok, err = pcall(cmds[v.cmd], v) end
        if not ok then
            bootcfg = {}
            printError("Could not run boot script: " .. err)
            print("Press any key to continue.")
            os.pullEventRaw("key")
            return false
        end
    end
    if not bootcfg.fn then
        bootcfg = {}
        printError("Could not run boot script: missing boot type command")
        print("Press any key to continue.")
        os.pullEventRaw("key")
        return false
    end
    bootcfg.fn(table.unpack(bootcfg.args))
    return true
end

local runningDir
config = setmetatable({
    title = "Phoenix pxboot",
    titlecolor = colors.white,
    backgroundcolor = colors.black,
    textcolor = colors.white,
    boxcolor = colors.white,
    boxbackground = colors.black,
    selectcolor = colors.white,
    selecttext = colors.black,
    background = nil,
    defaultentry = nil,
    timeout = 30,

    menuentry = function(name)
        expect(1, name, "string")
        return function(entry)
            expect(2, entry, "table")
            local n = 1
            for i, v in pairs(entry) do if type(i) == "number" then n = math.max(i, n) end end
            local retval = {name = name, commands = {}}
            for i = 1, n do
                local c = entry[i]
                if (type(c) ~= "table" and type(c) ~= "function") or not c.cmd then error("bad command entry #" .. i .. (c == nil and " (unknown command)" or " (missing arguments)"), 2) end
                if type(c) == "function" then retval.commands[#retval.commands+1] = c
                elseif c.cmd == "description" then retval.description = c.text
                elseif cmds[c.cmd] then retval.commands[#retval.commands+1] = c
                else error("bad command entry #" .. i .. " (unknown command " .. c.cmd .. ")", 2) end
            end
            entries[#entries+1] = retval
            entry_names[name] = retval
        end
    end,
    include = function(path)
        expect(1, path, "string")
        if not path:match "^/" then path = fs.combine(runningDir, path) end
        for _, v in ipairs(fs.find(path)) do
            repeat
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
    end,
    loadmod = function(path, args)
        expect(1, path, "string")
        expect(2, args, "table", "nil")
        cmds.insmod {name = path, args = args, line = debug.getinfo(2, "l").currentline}
    end,

    description = function(text)
        expect(1, text, "string")
        return {cmd = "description", text = text, line = debug.getinfo(2, "l").currentline}
    end,
    kernel = function(path)
        expect(1, path, "string")
        return {cmd = "kernel", path = path, line = debug.getinfo(2, "l").currentline}
    end,
    chainloader = function(path)
        expect(1, path, "string")
        return {cmd = "chainloader", path = path, line = debug.getinfo(2, "l").currentline}
    end,
    args = function(args)
        expect(1, args, "string", "table")
        if type(args) == "table" then
            return {cmd = "args", args = args, line = debug.getinfo(2, "l").currentline}
        else
            local t = {""}
            local q
            for c in args:gmatch "." do
                if q then
                    if c == q then q = nil
                    else t[#t] = t[#t] .. c end
                elseif c == '"' or c == "'" then q = c
                elseif c == ' ' then t[#t+1] = ""
                else t[#t] = t[#t] .. c end
            end
            local n = 2
            return setmetatable({cmd = "args", args = t, line = debug.getinfo(2, "l").currentline}, {__call = function(self, arg)
                expect(n, arg, "string")
                n=n+1
                local t = self.args
                local q
                t[#t+1] = ""
                for c in arg:gmatch "." do
                    if q then
                        if c == q then q = nil
                        else t[#t] = t[#t] .. c end
                    elseif c == '"' or c == "'" then q = c
                    elseif c == ' ' then t[#t+1] = ""
                    else t[#t] = t[#t] .. c end
                end
                return self
            end})
        end
    end,
    craftos = {cmd = "craftos"},
    global = function(key)
        return function(value)
            return {cmd = "global", key = key, value = value}
        end
    end,
    monitor = function(name)
        return {cmd = "monitor", name = name}
    end,
    insmod = function(name)
        expect(1, name, "string")
        return setmetatable({cmd = "insmod", name = name, line = debug.getinfo(2, "l").currentline}, {__call = function(self, args)
            expect(2, args, "table")
            self.args = args
            setmetatable(self, nil)
            return self
        end})
    end
}, {__index = _ENV})

term.clear()
term.setCursorPos(1, 1)

repeat
    local fn, err = loadfile(shell and fs.combine(fs.getDir(shell.getRunningProgram()), "config.lua") or "pxboot/config.lua", "t", config)
    if not fn then
        printError("Could not load config file: " .. err)
        print("Press any key to continue...")
        os.pullEvent("key")
        break
    end
    runningDir = shell and fs.getDir(shell.getRunningProgram()) or "pxboot"
    local ok, err = pcall(fn)
    runningDir = nil
    if not ok then
        printError("Failed to execute config file: " .. err)
        print("Press any key to continue...")
        os.pullEvent("key")
        break
    end
until true

local function runShell()

end

if #entries == 0 then return runShell() end

local function hex(n) return ("0123456789abcdef"):sub(n, n) end

local w, h = term.getSize()
local enth = h - 11
local boxwin = window.create(term.current(), 2, 4, w - 2, h - 9)
local entrywin = window.create(boxwin, 2, 2, w - 4, enth)

term.setBackgroundColor(config.backgroundcolor)
term.clear()
boxwin.setBackgroundColor(config.boxbackground or config.backgroundcolor)
boxwin.clear()
entrywin.setBackgroundColor(config.boxbackground or config.backgroundcolor)
entrywin.clear()

local selection, scroll = 1, 1
if config.defaultentry then
    for i = 1, #entries do if entries[i].name == config.defaultentry then selection = i break end end
    if config.timeout == 0 and boot(entries[selection]) then return end
end
local function drawEntries()
    entrywin.setVisible(false)
    entrywin.setBackgroundColor(config.boxbackground or config.backgroundcolor)
    entrywin.clear()
    for i = scroll, scroll + enth - 1 do
        local e = entries[i]
        if not e then break end
        entrywin.setCursorPos(2, i - scroll + 1)
        if i == selection then
            entrywin.setBackgroundColor(config.selectcolor)
            entrywin.setTextColor(config.selecttext)
        else
            entrywin.setBackgroundColor(config.boxbackground or config.backgroundcolor)
            entrywin.setTextColor(config.textcolor)
        end
        entrywin.clearLine()
        entrywin.write(#e.name > w-6 and e.name:sub(1, w-9) .. "..." or e.name)
        if i == selection and config.timeout then
            local s = tostring(config.timeout)
            entrywin.setCursorPos(w - 4 - #s, i - scroll + 1)
            entrywin.write(s)
            entrywin.setCursorPos(2, i - scroll + 1)
        end
    end
    entrywin.setVisible(true)
    term.setCursorPos(5, h - 5)
    term.clearLine()
    term.setTextColor(config.titlecolor)
    term.write(entries[selection].description or "")
end

local function drawScreen()
    local bbg, bfg = hex(select(2, math.frexp(config.boxbackground or config.backgroundcolor))), hex(select(2, math.frexp(config.boxcolor or config.textcolor)))
    boxwin.setTextColor(config.boxcolor or config.textcolor)
    boxwin.setCursorPos(1, 1)
    boxwin.write("\x9C" .. ("\x8C"):rep(w - 4))
    boxwin.blit("\x93", bbg, bfg)
    for y = 2, h - 10 do
        boxwin.setCursorPos(1, y)
        boxwin.blit("\x95", bfg, bbg)
        boxwin.setCursorPos(w - 2, y)
        boxwin.blit("\x95", bbg, bfg)
    end
    boxwin.setCursorPos(1, h - 9)
    boxwin.setBackgroundColor(config.boxbackground or config.backgroundcolor)
    boxwin.setTextColor(config.boxcolor or config.textcolor)
    boxwin.write("\x8D" .. ("\x8C"):rep(w - 4) .. "\x8E")

    term.setCursorPos((w - #config.title) / 2, 2)
    term.setTextColor(config.titlecolor or config.textcolor)
    term.write(config.title)
    term.setCursorPos(5, h - 3)
    term.write("Use the \x18 and \x19 keys to select.")
    term.setCursorPos(5, h - 2)
    term.write("Press enter to boot the selected OS.")
    --term.setCursorPos(5, h - 1)
    --term.write("'c' for shell, 'e' to edit.")

    drawEntries()
end
term.setBackgroundColor(config.backgroundcolor)
term.clear()
drawScreen()

local tm = config.defaultentry and config.timeout and os.startTimer(1)
while true do
    local ev = {coroutine.yield()}
    if ev[1] == "timer" and ev[2] == tm then
        config.timeout = config.timeout - 1
        if config.timeout == 0 then if boot(entry_names[config.defaultentry]) then return end end
        drawEntries()
        tm = os.startTimer(1)
    elseif ev[1] == "key" then
        if tm then
            os.cancelTimer(tm)
            config.timeout, tm = nil
            drawEntries()
        end
        if (ev[2] == keys.down or ev[2] == keys.numPad2) and selection < #entries then
            selection = selection + 1
            if selection > scroll + enth - 1 then scroll = scroll + 1 end
            drawEntries()
        elseif (ev[2] == keys.up or ev[2] == keys.numPad8) and selection > 1 then
            selection = selection - 1
            if selection < scroll then scroll = scroll - 1 end
            drawEntries()
        elseif ev[2] == keys.enter then
            if boot(entries[selection]) then return end
            term.clear()
            drawScreen()
        --[[elseif ev[2] == keys.c then
            runShell()
            drawScreen()]]
        end
    elseif ev[1] == "terminate" then break
    end
end
