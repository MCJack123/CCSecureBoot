loadmod "codesign"

title = "Secure Boot"
defaultentry = "startup.lua"
timeout = 0

menuentry "startup.lua" {
    description "Default startup file";
    chainloader "/startup.lua";
}

include "/pxboot_config.lua"
include "/disk/pxboot_config.lua"
