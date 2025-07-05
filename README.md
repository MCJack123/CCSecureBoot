# CCSecureBoot
Implements boot security in CC: Tweaked.

## Installation
CC: Tweaked 1.112.0 or later must already be installed.

Simply install a built JAR into your `mods` folder. This mod only operates on the server side, so multiplayer clients do not need it installed.

## Usage
By default, secure boot is disabled for all computers. To enable secure boot for a computer, run the `enroll-secure-boot` program. This program will generate a new key for the computer, placing it on a floppy disk for safe keeping.

`enroll-secure-boot` will first display some important information about secure boot, and asks for confirmation to continue. Then it will prompt for a password for the key - this is optional, but recommended to prevent accidental key leakage. If a disk isn't detected, it will then wait for a disk to be inserted. Once ready, the key will be generated and saved, and a recovery boot config will be placed on the disk as well.

When secure boot is enabled, the computer will only be able to boot from files that have a signature alongside them. Files can be signed with the `sign` command, which will create a `.sig` file next to the program. The key disk must be in a disk drive to sign.

Secure boot disables direct access to the shell - it will only boot to `startup.lua` by default (which must be signed). If the key disk is inserted, a boot menu will appear with the option to start a shell.

Secure boot runs on [pxboot](https://github.com/Phoenix-ComputerCraft/pxboot), which allows customizing the boot screen, including adding more menu entries, changing the default entry and timeout, and stylizing the menu. Additional configs can be loaded from `/pxboot_config.lua`, which must be signed as well. See the repo for more information on how to write configs for pxboot.

Secure boot may be disabled for a computer by running `unenroll-secure-boot` on any computer with the key card inserted. The computer is unenrolled by key card, not by computer ID, so a computer which cannot be booted anymore can be unenrolled. The key will be revoked as well, which allows preventing abuse if a key is leaked.

If the key for a computer is lost, there is no way to recover the computer - it will no longer be possible to modify the boot files or unenroll the computer from secure boot. Keep the key disk in a safe place, away from other players.

## Securing your code
Secure boot only ensures a root of trust going into your program - it does not guarantee that your computer as a whole is safe. It is up to you to make sure your code is secure from hacks, including checking all code that's loaded and avoiding unsafe programs.

When secure boot is enabled, due to the way the boot manager is set up, you are automatically protected from the two most basic bypasses for programs: holding Ctrl+T to terminate to the shell, and inserting a disk with a startup file. You won't have to protect against these in your program (though you should ideally handle `terminate` events safely instead of erroring and restarting).

To help with code signing, CCSecureBoot exposes an easy-to-use library based on the same code that the boot manager uses. Simply call `dofile("/rom/modules/main/codesign.lua")` to gain access to a few functions that make checking signatures easier:
- `codesign.verify(path)`: Simply verifies the signature of a file, and returns a boolean whether the file is safe.
- `codesign.execute(cmd, ...)`: A wrapper for `shell.execute` that checks the signature of the command. This doesn't allow ROM programs, however - use normal `shell.execute` to run known safe programs.
- `codesign.loadfile(path, mode, env)`: A wrapper for `loadfile` that checks the signature of the file. This automatically allows modules in `/rom/modules`, but will not work for the rest of the ROM.
- `codesign.dofile(path)`: A wrapper for `dofile` that checks the signature of the file. This automatically allows modules in `/rom/modules`, but will not work for the rest of the ROM.
- `codesign.enforceModuleSigning()`: Requires code signing on all modules loaded through `require`. Call this once at the start of your program - it will stay active for the rest of the program's lifetime. This does not survive inside `codesign.execute`/`shell.execute` calls - call it again inside a new program.
- `codesign.sign(data, password)`: Generates a signature blob for the data provided. This is in the same format as `.sig` files. The key disk must be inserted, and if the key is password-protected, the password must be provided.
- `codesign.load(data, sig, name, mode, env)`: A wrapper for `load` that checks the signature of the code, using a provided signature blob.

If your program uses modules via `require`, enable module signing before loading any modules, to make sure they are properly signed and not replaced with untrusted code:

```lua
-- require could load a local module instead of the one in ROM - always use dofile to load codesign:
local codesign = dofile "/rom/modules/main/codesign.lua"
codesign.enforceModuleSigning()
-- Now require is safe to load external modules:
local yourmod = require "yourmod"
-- ...
```

As a reminder, never load untrusted code through `load` without a restricted environment, especially when the input is from a modem. If you want to load code, give it a highly restricted environment with only the functions required, if any. (Despite the fact that `textutils.unserialize` loads code, it uses an empty environment, so it's considered safe.)

## Inner workings
CCSecureBoot uses the PKCS or S/MIME protocol stack for storing cryptographic info, and uses Ed25519 for signatures. Most of the heavy lifting is done by [libcert](https://github.com/Phoenix-ComputerCraft/libcert) and [ccryptolib](https://github.com/migeyel/ccryptolib) on the Lua side, and [Bouncy Castle](https://www.bouncycastle.org) on the Java side.

The server keeps a unique private key, stored in `computercraft/root.key` in the save directory, and an associated certificate, stored in `computercraft/certs/root.pem`. These are used as a root of trust for the server. Computers can then request certificates for themselves signed by the root certificate, which are traced back to the root on verification. Requests are passed through a Java API which is hidden behind a `require` call.

CCSecureBoot inserts a program into `/rom/autorun` which checks for enrollment, and if the current computer is enrolled then it runs pxboot. It checks enrollment by looking for `/rom/pxboot/certs/enrolled/<id>`, where `/rom/pxboot/certs` is a save mount located in `computercraft/certs` (allowing the mod to edit it at runtime).

The version of pxboot used includes a module which inserts a signature check into all commands which load code. Signatures are stored in PEM-encoded PKCS#7 containers next to the files which must be signed, and contain the certificate of the signer alongside the signature. This allows the signature to stand alone without needing to have a separate list of valid certificates - the embedded cert can be validated against the trusted root.

Enrolling in secure boot involves generating a PKCS#10 signing request for the current computer ID. The computer first generates a private key, and then creates a signing request for the associated public key. The CSR contains a field in the subject, `uniqueIdentifier` (OID `2.5.4.45`), which contains the computer's ID. This ID must match the running computer, otherwise the signing request will be rejected.

The CSR is then passed off to the server in PEM format to sign, using `secureboot.enroll(csr)`. If the IDs match, the new X.509 certificate is passed back (PEM-encoded), and a file is created in `computercraft/certs/enrolled`/`/rom/pxboot/certs/enrolled` for the computer ID, telling the bootloader to check signatures.

Afterward, the certificate and key are saved in X.509 and PKCS#8 formats, respectively, both PEM-encoded. For safety, a boot config and startup program for loading the shell are created on the disk, which are then signed with the new key.

Signing is a simple PKCS#7 signature operation, using the certificate and key stored on the floppy disk.

Unenrolling involves calling `secureboot.unenroll(cert, signature)` with the computer's certificate (PEM-encoded X.509), as well as a signed challenge string. The challenge text is simply the ID of the target computer as a string, and the signature is passed as a bare Ed25519 signature, foregoing any PKCS#7 wrapper for simplicity (since there's no easy PKCS#7 signature checking in Java). If the certificate is valid and the signature passes, the enrollment file is deleted and the certificate is stored in a certificate revocation list, stored at `computercraft/certs/revoked.crl`.

## License
CCSecureBoot is licensed under MPLv2, with portions licensed under MIT.
