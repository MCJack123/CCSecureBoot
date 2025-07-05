local libcert = require "cert"
local random = require "ccryptolib.random"
local secureboot = require "secureboot"

if fs.exists("/rom/pxboot/certs/enrolled/" .. os.computerID()) then
    printError("This computer is already enrolled in secure boot. Use unenroll-secure-boot to unenroll first.")
    return
end

print("Enrolling in secure boot will require all boot scripts to be signed with a key to be able to run on this computer. This ensures that nobody but you can place code on your computer. The key will be saved on a floppy disk for safekeeping.")
term.setTextColor(colors.yellow)
print("Be aware that secure boot only protects the path up to your code. It is up to you to make sure your code can't be terminated or run untrusted code.")
term.setTextColor(colors.red)
print("If you lose the key, you will be permanently unable to modify the boot files on this computer. If another player gains access to the key, they can modify the computer's code as they wish. Keep it in a safe place, out of reach of other players!")
term.setTextColor(colors.lightBlue)
print("Secure boot may be disabled in the future by running unenroll-secure-boot on any computer with the key disk inserted. This will revoke the key, meaning the key will never again be usable on that computer - this is useful if the key gets leaked.")
term.setTextColor(colors.white)
write("Do you wish to continue? (y/N) ")
local response = read()
if response:lower() ~= "y" then return end

write("Enter your name: ")
local name = read()
while name == "" do
    write("Name must not be empty.\nEnter your name: ")
    name = read()
end
write("Enter a password for the key (leave blank for no password): ")
local password = read("\7")
if password == "" then password = nil end

if not fs.isDir("/disk") then
    print("Please insert a floppy disk into an attached disk drive. This disk will become the key for the computer.")
    while not fs.isDir("/disk") do os.pullEvent("disk") end
end
    
print("Generating key...")
random.initWithTiming()
local key, pk8 = libcert.generatePrivateKeyForSigning(password)
print("Saving key...")
local file, err = fs.open("/disk/secure-boot-" .. os.computerID() .. ".key", "wb")
if not file then
    printError("An error occurred while saving the key to disk (" .. err .. "). The computer has not been enrolled in secure boot. Make sure the disk is writable and has enough free space.")
    return
end
file.write(pk8)
file.close()
print("Generating certificate request...")
local pk10 = libcert.generateCSR(pk8, {
    [libcert.container.nameOIDs.commonName] = name,
    [libcert.container.nameOIDs.uniqueIdentifier] = tostring(os.computerID())
}, password)
sleep(0)
print("Requesting certificate from server...")
local cert = secureboot.enroll(pk10)
print("Saving certificate...")
file, err = fs.open("/disk/secure-boot-" .. os.computerID() .. ".pem", "wb")
if not file then
    pcall(fs.delete, "/disk/secure-boot-" .. os.computerID() .. ".key")
    secureboot.unenroll(cert, libcert.sign(cert, pk8, tostring(os.computerID()), nil, password))
    printError("An error occurred while saving the key to disk (" .. err .. "). The computer has been unenrolled in secure boot. Make sure the disk is writable and has enough free space.")
    return
end
file.write(cert)
file.close()
sleep(0)

local pxboot_config = [[
defaultentry = nil
timeout = 15

menuentry "Rescue shell" {
    description "Boot the CraftOS shell. (insecure)";
    chainloader "/disk/startup.lua";
}
]]
print("Creating rescue files...")
file, err = fs.open("/disk/pxboot_config.lua", "wb")
if file then
    file.write(pxboot_config)
    file.close()
    file, err = fs.open("/disk/pxboot_config.lua.sig", "wb")
    if file then
        file.write(libcert.sign(cert, pk8, pxboot_config, nil, password))
        file.close()
    else
        printError("Could not write pxboot_config.lua.sig (" ..
        err .. "). The computer was enrolled successfully, but the key disk cannot be used to rescue the computer.")
    end
else
    printError("Could not write pxboot_config.lua (" ..
    err .. "). The computer was enrolled successfully, but the key disk cannot be used to rescue the computer.")
end
sleep(0)
file, err = fs.open("/disk/startup.lua", "wb")
if file then
    file.write('shell.run("shell")')
    file.close()
    file, err = fs.open("/disk/startup.lua.sig", "wb")
    if file then
        file.write(libcert.sign(cert, pk8, 'shell.run("shell")', nil, password))
        file.close()
    else
        printError("Could not write startup.lua.sig (" .. err .. "). The computer was enrolled successfully, but the key disk cannot be used to rescue the computer.")
    end
else
    printError("Could not write startup.lua (" .. err .. "). The computer was enrolled successfully, but the key disk cannot be used to rescue the computer.")
end

term.setTextColor(colors.lime)
print("Secure boot has successfully been enrolled for this computer. All boot files must now be signed with your key.")
term.setTextColor(colors.lightBlue)
print("Use the 'sign' command to sign any file on the system.")
term.setTextColor(colors.yellow)
print("The default boot config immediately boots to /startup.lua. You may add alternate boot options with a pxboot config file at /pxboot_config.lua, which must also be signed to be usable.")
term.setTextColor(colors.orange)
print("For more information on pxboot, visit https://github.com/Phoenix-ComputerCraft/pxboot.")
term.setTextColor(colors.white)