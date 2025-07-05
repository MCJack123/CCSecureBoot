if fs.exists("/rom/pxboot/certs/enrolled/" .. os.computerID()) then
    while true do shell.run("/rom/pxboot/pxboot.lua") end
end