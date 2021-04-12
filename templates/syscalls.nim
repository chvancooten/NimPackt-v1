{.passC:"-masm=intel".}

# Contains direct syscalls
# Generated with NimlineWhispers by ajpc500
# Function names are renamed since they will be readable in the binary

# NtAllocateVirtualMemory -> tmNeIICXlJFvSEkq
# NtWriteVirtualMemory -> VfSxUkLKbMoGGBeT
# NtOpenProcess -> ypSZHQjRZBuZvYgv
# NtCreateThreadEx -> eTvGYJYHUrfXKwzj
# NtClose -> NAdBghYPVEdFHrzq
# NtProtectVirtualMemory -> ubtkgykehoOtMXRG

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

proc tmNeIICXlJFvSEkq*(ProcessHandle: HANDLE, BaseAddress: PVOID, ZeroBits: ULONG, RegionSize: PSIZE_T, AllocationType: ULONG, Protect: ULONG): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                                 
tmNeIICXlJFvSEkq_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  tmNeIICXlJFvSEkq_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  tmNeIICXlJFvSEkq_Check_10_0_XXXX
	jmp tmNeIICXlJFvSEkq_SystemCall_Unknown
tmNeIICXlJFvSEkq_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  tmNeIICXlJFvSEkq_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  tmNeIICXlJFvSEkq_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  tmNeIICXlJFvSEkq_SystemCall_6_3_XXXX
	jmp tmNeIICXlJFvSEkq_SystemCall_Unknown
tmNeIICXlJFvSEkq_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  tmNeIICXlJFvSEkq_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  tmNeIICXlJFvSEkq_SystemCall_6_1_7601
	jmp tmNeIICXlJFvSEkq_SystemCall_Unknown
tmNeIICXlJFvSEkq_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  tmNeIICXlJFvSEkq_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  tmNeIICXlJFvSEkq_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  tmNeIICXlJFvSEkq_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  tmNeIICXlJFvSEkq_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  tmNeIICXlJFvSEkq_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  tmNeIICXlJFvSEkq_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  tmNeIICXlJFvSEkq_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  tmNeIICXlJFvSEkq_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  tmNeIICXlJFvSEkq_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  tmNeIICXlJFvSEkq_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  tmNeIICXlJFvSEkq_SystemCall_10_0_19042
	jmp tmNeIICXlJFvSEkq_SystemCall_Unknown
tmNeIICXlJFvSEkq_SystemCall_6_1_7600:          
	mov eax, 0x0015
	jmp tmNeIICXlJFvSEkq_Epilogue
tmNeIICXlJFvSEkq_SystemCall_6_1_7601:          
	mov eax, 0x0015
	jmp tmNeIICXlJFvSEkq_Epilogue
tmNeIICXlJFvSEkq_SystemCall_6_2_XXXX:          
	mov eax, 0x0016
	jmp tmNeIICXlJFvSEkq_Epilogue
tmNeIICXlJFvSEkq_SystemCall_6_3_XXXX:          
	mov eax, 0x0017
	jmp tmNeIICXlJFvSEkq_Epilogue
tmNeIICXlJFvSEkq_SystemCall_10_0_10240:        
	mov eax, 0x0018
	jmp tmNeIICXlJFvSEkq_Epilogue
tmNeIICXlJFvSEkq_SystemCall_10_0_10586:        
	mov eax, 0x0018
	jmp tmNeIICXlJFvSEkq_Epilogue
tmNeIICXlJFvSEkq_SystemCall_10_0_14393:        
	mov eax, 0x0018
	jmp tmNeIICXlJFvSEkq_Epilogue
tmNeIICXlJFvSEkq_SystemCall_10_0_15063:        
	mov eax, 0x0018
	jmp tmNeIICXlJFvSEkq_Epilogue
tmNeIICXlJFvSEkq_SystemCall_10_0_16299:        
	mov eax, 0x0018
	jmp tmNeIICXlJFvSEkq_Epilogue
tmNeIICXlJFvSEkq_SystemCall_10_0_17134:        
	mov eax, 0x0018
	jmp tmNeIICXlJFvSEkq_Epilogue
tmNeIICXlJFvSEkq_SystemCall_10_0_17763:        
	mov eax, 0x0018
	jmp tmNeIICXlJFvSEkq_Epilogue
tmNeIICXlJFvSEkq_SystemCall_10_0_18362:        
	mov eax, 0x0018
	jmp tmNeIICXlJFvSEkq_Epilogue
tmNeIICXlJFvSEkq_SystemCall_10_0_18363:        
	mov eax, 0x0018
	jmp tmNeIICXlJFvSEkq_Epilogue
tmNeIICXlJFvSEkq_SystemCall_10_0_19041:        
	mov eax, 0x0018
	jmp tmNeIICXlJFvSEkq_Epilogue
tmNeIICXlJFvSEkq_SystemCall_10_0_19042:        
	mov eax, 0x0018
	jmp tmNeIICXlJFvSEkq_Epilogue
tmNeIICXlJFvSEkq_SystemCall_Unknown:           
	ret
tmNeIICXlJFvSEkq_Epilogue:
	mov r10, rcx
	syscall
	ret
    """

proc NAdBghYPVEdFHrzq*(Handle: HANDLE): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                 
NAdBghYPVEdFHrzq_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  NAdBghYPVEdFHrzq_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  NAdBghYPVEdFHrzq_Check_10_0_XXXX
	jmp NAdBghYPVEdFHrzq_SystemCall_Unknown
NAdBghYPVEdFHrzq_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  NAdBghYPVEdFHrzq_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  NAdBghYPVEdFHrzq_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  NAdBghYPVEdFHrzq_SystemCall_6_3_XXXX
	jmp NAdBghYPVEdFHrzq_SystemCall_Unknown
NAdBghYPVEdFHrzq_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  NAdBghYPVEdFHrzq_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  NAdBghYPVEdFHrzq_SystemCall_6_1_7601
	jmp NAdBghYPVEdFHrzq_SystemCall_Unknown
NAdBghYPVEdFHrzq_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  NAdBghYPVEdFHrzq_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  NAdBghYPVEdFHrzq_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  NAdBghYPVEdFHrzq_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  NAdBghYPVEdFHrzq_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  NAdBghYPVEdFHrzq_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  NAdBghYPVEdFHrzq_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  NAdBghYPVEdFHrzq_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  NAdBghYPVEdFHrzq_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  NAdBghYPVEdFHrzq_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  NAdBghYPVEdFHrzq_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  NAdBghYPVEdFHrzq_SystemCall_10_0_19042
	jmp NAdBghYPVEdFHrzq_SystemCall_Unknown
NAdBghYPVEdFHrzq_SystemCall_6_1_7600:          
	mov eax, 0x000c
	jmp NAdBghYPVEdFHrzq_Epilogue
NAdBghYPVEdFHrzq_SystemCall_6_1_7601:          
	mov eax, 0x000c
	jmp NAdBghYPVEdFHrzq_Epilogue
NAdBghYPVEdFHrzq_SystemCall_6_2_XXXX:          
	mov eax, 0x000d
	jmp NAdBghYPVEdFHrzq_Epilogue
NAdBghYPVEdFHrzq_SystemCall_6_3_XXXX:          
	mov eax, 0x000e
	jmp NAdBghYPVEdFHrzq_Epilogue
NAdBghYPVEdFHrzq_SystemCall_10_0_10240:        
	mov eax, 0x000f
	jmp NAdBghYPVEdFHrzq_Epilogue
NAdBghYPVEdFHrzq_SystemCall_10_0_10586:        
	mov eax, 0x000f
	jmp NAdBghYPVEdFHrzq_Epilogue
NAdBghYPVEdFHrzq_SystemCall_10_0_14393:        
	mov eax, 0x000f
	jmp NAdBghYPVEdFHrzq_Epilogue
NAdBghYPVEdFHrzq_SystemCall_10_0_15063:        
	mov eax, 0x000f
	jmp NAdBghYPVEdFHrzq_Epilogue
NAdBghYPVEdFHrzq_SystemCall_10_0_16299:        
	mov eax, 0x000f
	jmp NAdBghYPVEdFHrzq_Epilogue
NAdBghYPVEdFHrzq_SystemCall_10_0_17134:        
	mov eax, 0x000f
	jmp NAdBghYPVEdFHrzq_Epilogue
NAdBghYPVEdFHrzq_SystemCall_10_0_17763:        
	mov eax, 0x000f
	jmp NAdBghYPVEdFHrzq_Epilogue
NAdBghYPVEdFHrzq_SystemCall_10_0_18362:        
	mov eax, 0x000f
	jmp NAdBghYPVEdFHrzq_Epilogue
NAdBghYPVEdFHrzq_SystemCall_10_0_18363:        
	mov eax, 0x000f
	jmp NAdBghYPVEdFHrzq_Epilogue
NAdBghYPVEdFHrzq_SystemCall_10_0_19041:        
	mov eax, 0x000f
	jmp NAdBghYPVEdFHrzq_Epilogue
NAdBghYPVEdFHrzq_SystemCall_10_0_19042:        
	mov eax, 0x000f
	jmp NAdBghYPVEdFHrzq_Epilogue
NAdBghYPVEdFHrzq_SystemCall_Unknown:           
	ret
NAdBghYPVEdFHrzq_Epilogue:
	mov r10, rcx
	syscall
	ret
    """

proc eTvGYJYHUrfXKwzj*(ThreadHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, ProcessHandle: HANDLE, StartRoutine: PVOID, Argument: PVOID, CreateFlags: ULONG, ZeroBits: SIZE_T, StackSize: SIZE_T, MaximumStackSize: SIZE_T, AttributeList: PPS_ATTRIBUTE_LIST): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                          
eTvGYJYHUrfXKwzj_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  eTvGYJYHUrfXKwzj_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  eTvGYJYHUrfXKwzj_Check_10_0_XXXX
	jmp eTvGYJYHUrfXKwzj_SystemCall_Unknown
eTvGYJYHUrfXKwzj_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  eTvGYJYHUrfXKwzj_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  eTvGYJYHUrfXKwzj_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  eTvGYJYHUrfXKwzj_SystemCall_6_3_XXXX
	jmp eTvGYJYHUrfXKwzj_SystemCall_Unknown
eTvGYJYHUrfXKwzj_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  eTvGYJYHUrfXKwzj_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  eTvGYJYHUrfXKwzj_SystemCall_6_1_7601
	jmp eTvGYJYHUrfXKwzj_SystemCall_Unknown
eTvGYJYHUrfXKwzj_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  eTvGYJYHUrfXKwzj_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  eTvGYJYHUrfXKwzj_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  eTvGYJYHUrfXKwzj_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  eTvGYJYHUrfXKwzj_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  eTvGYJYHUrfXKwzj_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  eTvGYJYHUrfXKwzj_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  eTvGYJYHUrfXKwzj_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  eTvGYJYHUrfXKwzj_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  eTvGYJYHUrfXKwzj_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  eTvGYJYHUrfXKwzj_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  eTvGYJYHUrfXKwzj_SystemCall_10_0_19042
	jmp eTvGYJYHUrfXKwzj_SystemCall_Unknown
eTvGYJYHUrfXKwzj_SystemCall_6_1_7600:          
	mov eax, 0x00a5
	jmp eTvGYJYHUrfXKwzj_Epilogue
eTvGYJYHUrfXKwzj_SystemCall_6_1_7601:          
	mov eax, 0x00a5
	jmp eTvGYJYHUrfXKwzj_Epilogue
eTvGYJYHUrfXKwzj_SystemCall_6_2_XXXX:          
	mov eax, 0x00af
	jmp eTvGYJYHUrfXKwzj_Epilogue
eTvGYJYHUrfXKwzj_SystemCall_6_3_XXXX:          
	mov eax, 0x00b0
	jmp eTvGYJYHUrfXKwzj_Epilogue
eTvGYJYHUrfXKwzj_SystemCall_10_0_10240:        
	mov eax, 0x00b3
	jmp eTvGYJYHUrfXKwzj_Epilogue
eTvGYJYHUrfXKwzj_SystemCall_10_0_10586:        
	mov eax, 0x00b4
	jmp eTvGYJYHUrfXKwzj_Epilogue
eTvGYJYHUrfXKwzj_SystemCall_10_0_14393:        
	mov eax, 0x00b6
	jmp eTvGYJYHUrfXKwzj_Epilogue
eTvGYJYHUrfXKwzj_SystemCall_10_0_15063:        
	mov eax, 0x00b9
	jmp eTvGYJYHUrfXKwzj_Epilogue
eTvGYJYHUrfXKwzj_SystemCall_10_0_16299:        
	mov eax, 0x00ba
	jmp eTvGYJYHUrfXKwzj_Epilogue
eTvGYJYHUrfXKwzj_SystemCall_10_0_17134:        
	mov eax, 0x00bb
	jmp eTvGYJYHUrfXKwzj_Epilogue
eTvGYJYHUrfXKwzj_SystemCall_10_0_17763:        
	mov eax, 0x00bc
	jmp eTvGYJYHUrfXKwzj_Epilogue
eTvGYJYHUrfXKwzj_SystemCall_10_0_18362:        
	mov eax, 0x00bd
	jmp eTvGYJYHUrfXKwzj_Epilogue
eTvGYJYHUrfXKwzj_SystemCall_10_0_18363:        
	mov eax, 0x00bd
	jmp eTvGYJYHUrfXKwzj_Epilogue
eTvGYJYHUrfXKwzj_SystemCall_10_0_19041:        
	mov eax, 0x00c1
	jmp eTvGYJYHUrfXKwzj_Epilogue
eTvGYJYHUrfXKwzj_SystemCall_10_0_19042:        
	mov eax, 0x00c1
	jmp eTvGYJYHUrfXKwzj_Epilogue
eTvGYJYHUrfXKwzj_SystemCall_Unknown:           
	ret
eTvGYJYHUrfXKwzj_Epilogue:
	mov r10, rcx
	syscall
	ret
    """

proc ypSZHQjRZBuZvYgv*(ProcessHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, ClientId: PCLIENT_ID): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                       
ypSZHQjRZBuZvYgv_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  ypSZHQjRZBuZvYgv_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  ypSZHQjRZBuZvYgv_Check_10_0_XXXX
	jmp ypSZHQjRZBuZvYgv_SystemCall_Unknown
ypSZHQjRZBuZvYgv_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  ypSZHQjRZBuZvYgv_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  ypSZHQjRZBuZvYgv_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  ypSZHQjRZBuZvYgv_SystemCall_6_3_XXXX
	jmp ypSZHQjRZBuZvYgv_SystemCall_Unknown
ypSZHQjRZBuZvYgv_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  ypSZHQjRZBuZvYgv_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  ypSZHQjRZBuZvYgv_SystemCall_6_1_7601
	jmp ypSZHQjRZBuZvYgv_SystemCall_Unknown
ypSZHQjRZBuZvYgv_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  ypSZHQjRZBuZvYgv_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  ypSZHQjRZBuZvYgv_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  ypSZHQjRZBuZvYgv_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  ypSZHQjRZBuZvYgv_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  ypSZHQjRZBuZvYgv_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  ypSZHQjRZBuZvYgv_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  ypSZHQjRZBuZvYgv_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  ypSZHQjRZBuZvYgv_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  ypSZHQjRZBuZvYgv_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  ypSZHQjRZBuZvYgv_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  ypSZHQjRZBuZvYgv_SystemCall_10_0_19042
	jmp ypSZHQjRZBuZvYgv_SystemCall_Unknown
ypSZHQjRZBuZvYgv_SystemCall_6_1_7600:          
	mov eax, 0x0023
	jmp ypSZHQjRZBuZvYgv_Epilogue
ypSZHQjRZBuZvYgv_SystemCall_6_1_7601:          
	mov eax, 0x0023
	jmp ypSZHQjRZBuZvYgv_Epilogue
ypSZHQjRZBuZvYgv_SystemCall_6_2_XXXX:          
	mov eax, 0x0024
	jmp ypSZHQjRZBuZvYgv_Epilogue
ypSZHQjRZBuZvYgv_SystemCall_6_3_XXXX:          
	mov eax, 0x0025
	jmp ypSZHQjRZBuZvYgv_Epilogue
ypSZHQjRZBuZvYgv_SystemCall_10_0_10240:        
	mov eax, 0x0026
	jmp ypSZHQjRZBuZvYgv_Epilogue
ypSZHQjRZBuZvYgv_SystemCall_10_0_10586:        
	mov eax, 0x0026
	jmp ypSZHQjRZBuZvYgv_Epilogue
ypSZHQjRZBuZvYgv_SystemCall_10_0_14393:        
	mov eax, 0x0026
	jmp ypSZHQjRZBuZvYgv_Epilogue
ypSZHQjRZBuZvYgv_SystemCall_10_0_15063:        
	mov eax, 0x0026
	jmp ypSZHQjRZBuZvYgv_Epilogue
ypSZHQjRZBuZvYgv_SystemCall_10_0_16299:        
	mov eax, 0x0026
	jmp ypSZHQjRZBuZvYgv_Epilogue
ypSZHQjRZBuZvYgv_SystemCall_10_0_17134:        
	mov eax, 0x0026
	jmp ypSZHQjRZBuZvYgv_Epilogue
ypSZHQjRZBuZvYgv_SystemCall_10_0_17763:        
	mov eax, 0x0026
	jmp ypSZHQjRZBuZvYgv_Epilogue
ypSZHQjRZBuZvYgv_SystemCall_10_0_18362:        
	mov eax, 0x0026
	jmp ypSZHQjRZBuZvYgv_Epilogue
ypSZHQjRZBuZvYgv_SystemCall_10_0_18363:        
	mov eax, 0x0026
	jmp ypSZHQjRZBuZvYgv_Epilogue
ypSZHQjRZBuZvYgv_SystemCall_10_0_19041:        
	mov eax, 0x0026
	jmp ypSZHQjRZBuZvYgv_Epilogue
ypSZHQjRZBuZvYgv_SystemCall_10_0_19042:        
	mov eax, 0x0026
	jmp ypSZHQjRZBuZvYgv_Epilogue
ypSZHQjRZBuZvYgv_SystemCall_Unknown:           
	ret
ypSZHQjRZBuZvYgv_Epilogue:
	mov r10, rcx
	syscall
	ret
    """

proc VfSxUkLKbMoGGBeT*(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, NumberOfBytesToWrite: SIZE_T, NumberOfBytesWritten: PSIZE_T): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                              
VfSxUkLKbMoGGBeT_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  VfSxUkLKbMoGGBeT_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  VfSxUkLKbMoGGBeT_Check_10_0_XXXX
	jmp VfSxUkLKbMoGGBeT_SystemCall_Unknown
VfSxUkLKbMoGGBeT_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  VfSxUkLKbMoGGBeT_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  VfSxUkLKbMoGGBeT_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  VfSxUkLKbMoGGBeT_SystemCall_6_3_XXXX
	jmp VfSxUkLKbMoGGBeT_SystemCall_Unknown
VfSxUkLKbMoGGBeT_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  VfSxUkLKbMoGGBeT_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  VfSxUkLKbMoGGBeT_SystemCall_6_1_7601
	jmp VfSxUkLKbMoGGBeT_SystemCall_Unknown
VfSxUkLKbMoGGBeT_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  VfSxUkLKbMoGGBeT_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  VfSxUkLKbMoGGBeT_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  VfSxUkLKbMoGGBeT_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  VfSxUkLKbMoGGBeT_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  VfSxUkLKbMoGGBeT_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  VfSxUkLKbMoGGBeT_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  VfSxUkLKbMoGGBeT_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  VfSxUkLKbMoGGBeT_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  VfSxUkLKbMoGGBeT_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  VfSxUkLKbMoGGBeT_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  VfSxUkLKbMoGGBeT_SystemCall_10_0_19042
	jmp VfSxUkLKbMoGGBeT_SystemCall_Unknown
VfSxUkLKbMoGGBeT_SystemCall_6_1_7600:          
	mov eax, 0x0037
	jmp VfSxUkLKbMoGGBeT_Epilogue
VfSxUkLKbMoGGBeT_SystemCall_6_1_7601:          
	mov eax, 0x0037
	jmp VfSxUkLKbMoGGBeT_Epilogue
VfSxUkLKbMoGGBeT_SystemCall_6_2_XXXX:          
	mov eax, 0x0038
	jmp VfSxUkLKbMoGGBeT_Epilogue
VfSxUkLKbMoGGBeT_SystemCall_6_3_XXXX:          
	mov eax, 0x0039
	jmp VfSxUkLKbMoGGBeT_Epilogue
VfSxUkLKbMoGGBeT_SystemCall_10_0_10240:        
	mov eax, 0x003a
	jmp VfSxUkLKbMoGGBeT_Epilogue
VfSxUkLKbMoGGBeT_SystemCall_10_0_10586:        
	mov eax, 0x003a
	jmp VfSxUkLKbMoGGBeT_Epilogue
VfSxUkLKbMoGGBeT_SystemCall_10_0_14393:        
	mov eax, 0x003a
	jmp VfSxUkLKbMoGGBeT_Epilogue
VfSxUkLKbMoGGBeT_SystemCall_10_0_15063:        
	mov eax, 0x003a
	jmp VfSxUkLKbMoGGBeT_Epilogue
VfSxUkLKbMoGGBeT_SystemCall_10_0_16299:        
	mov eax, 0x003a
	jmp VfSxUkLKbMoGGBeT_Epilogue
VfSxUkLKbMoGGBeT_SystemCall_10_0_17134:        
	mov eax, 0x003a
	jmp VfSxUkLKbMoGGBeT_Epilogue
VfSxUkLKbMoGGBeT_SystemCall_10_0_17763:        
	mov eax, 0x003a
	jmp VfSxUkLKbMoGGBeT_Epilogue
VfSxUkLKbMoGGBeT_SystemCall_10_0_18362:        
	mov eax, 0x003a
	jmp VfSxUkLKbMoGGBeT_Epilogue
VfSxUkLKbMoGGBeT_SystemCall_10_0_18363:        
	mov eax, 0x003a
	jmp VfSxUkLKbMoGGBeT_Epilogue
VfSxUkLKbMoGGBeT_SystemCall_10_0_19041:        
	mov eax, 0x003a
	jmp VfSxUkLKbMoGGBeT_Epilogue
VfSxUkLKbMoGGBeT_SystemCall_10_0_19042:        
	mov eax, 0x003a
	jmp VfSxUkLKbMoGGBeT_Epilogue
VfSxUkLKbMoGGBeT_SystemCall_Unknown:           
	ret
VfSxUkLKbMoGGBeT_Epilogue:
	mov r10, rcx
	syscall
	ret
    """

proc ubtkgykehoOtMXRG*(ProcessHandle: HANDLE, BaseAddress: PVOID, RegionSize: PSIZE_T, NewProtect: ULONG, OldProtect: PULONG): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                                
ubtkgykehoOtMXRG_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  ubtkgykehoOtMXRG_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  ubtkgykehoOtMXRG_Check_10_0_XXXX
	jmp ubtkgykehoOtMXRG_SystemCall_Unknown
ubtkgykehoOtMXRG_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  ubtkgykehoOtMXRG_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  ubtkgykehoOtMXRG_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  ubtkgykehoOtMXRG_SystemCall_6_3_XXXX
	jmp ubtkgykehoOtMXRG_SystemCall_Unknown
ubtkgykehoOtMXRG_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  ubtkgykehoOtMXRG_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  ubtkgykehoOtMXRG_SystemCall_6_1_7601
	jmp ubtkgykehoOtMXRG_SystemCall_Unknown
ubtkgykehoOtMXRG_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  ubtkgykehoOtMXRG_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  ubtkgykehoOtMXRG_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  ubtkgykehoOtMXRG_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  ubtkgykehoOtMXRG_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  ubtkgykehoOtMXRG_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  ubtkgykehoOtMXRG_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  ubtkgykehoOtMXRG_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  ubtkgykehoOtMXRG_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  ubtkgykehoOtMXRG_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  ubtkgykehoOtMXRG_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  ubtkgykehoOtMXRG_SystemCall_10_0_19042
	jmp ubtkgykehoOtMXRG_SystemCall_Unknown
ubtkgykehoOtMXRG_SystemCall_6_1_7600:          
	mov eax, 0x004d
	jmp ubtkgykehoOtMXRG_Epilogue
ubtkgykehoOtMXRG_SystemCall_6_1_7601:          
	mov eax, 0x004d
	jmp ubtkgykehoOtMXRG_Epilogue
ubtkgykehoOtMXRG_SystemCall_6_2_XXXX:          
	mov eax, 0x004e
	jmp ubtkgykehoOtMXRG_Epilogue
ubtkgykehoOtMXRG_SystemCall_6_3_XXXX:          
	mov eax, 0x004f
	jmp ubtkgykehoOtMXRG_Epilogue
ubtkgykehoOtMXRG_SystemCall_10_0_10240:        
	mov eax, 0x0050
	jmp ubtkgykehoOtMXRG_Epilogue
ubtkgykehoOtMXRG_SystemCall_10_0_10586:        
	mov eax, 0x0050
	jmp ubtkgykehoOtMXRG_Epilogue
ubtkgykehoOtMXRG_SystemCall_10_0_14393:        
	mov eax, 0x0050
	jmp ubtkgykehoOtMXRG_Epilogue
ubtkgykehoOtMXRG_SystemCall_10_0_15063:        
	mov eax, 0x0050
	jmp ubtkgykehoOtMXRG_Epilogue
ubtkgykehoOtMXRG_SystemCall_10_0_16299:        
	mov eax, 0x0050
	jmp ubtkgykehoOtMXRG_Epilogue
ubtkgykehoOtMXRG_SystemCall_10_0_17134:        
	mov eax, 0x0050
	jmp ubtkgykehoOtMXRG_Epilogue
ubtkgykehoOtMXRG_SystemCall_10_0_17763:        
	mov eax, 0x0050
	jmp ubtkgykehoOtMXRG_Epilogue
ubtkgykehoOtMXRG_SystemCall_10_0_18362:        
	mov eax, 0x0050
	jmp ubtkgykehoOtMXRG_Epilogue
ubtkgykehoOtMXRG_SystemCall_10_0_18363:        
	mov eax, 0x0050
	jmp ubtkgykehoOtMXRG_Epilogue
ubtkgykehoOtMXRG_SystemCall_10_0_19041:        
	mov eax, 0x0050
	jmp ubtkgykehoOtMXRG_Epilogue
ubtkgykehoOtMXRG_SystemCall_10_0_19042:        
	mov eax, 0x0050
	jmp ubtkgykehoOtMXRG_Epilogue
ubtkgykehoOtMXRG_SystemCall_Unknown:           
	ret
ubtkgykehoOtMXRG_Epilogue:
	mov r10, rcx
	syscall
	ret
    """