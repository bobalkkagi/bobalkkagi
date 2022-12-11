from ctypes import *

from bobalkkagi.constValue import LdrBase, ProcessHeapBase, PshimDataBase


class UNICODE_STRING(Structure):
    _fields_ = [
        ("Length", c_uint16),
        ("MaximumLength", c_uint16),
        ("Buffer", c_wchar_p)
    ]

class LIST_ENTRY(Structure):
    _fields_ = [
        ("Flink", c_void_p),
        ("Blink", c_void_p)
    ]

class RTL_BALANCED_NODE(Structure):
    _fields_=[
        ("Left", c_void_p),
        ("Right", c_void_p),
        ("ParentValue", c_uint64)
    ]

class LARGE_INTEGER(Structure):
    _fields_=[
        ("LowPart", c_uint32),
        ("HighPart", c_int32),
    ]

class LDR_DATA_TABLE_ENTRY(Structure):
    _fields_ = [
        ("InLoadOrderLinks", LIST_ENTRY),
        ("InMemoryOrderLinks", LIST_ENTRY),
        ("InInitializationOrderLinks", LIST_ENTRY),
        ("DllBase", c_void_p),
        ("EntryPoint", c_void_p),
        ("SizeOfImage", c_uint32),
        ("FullDllName", UNICODE_STRING), # _UNICODE_STRING
        ("BaseDllName", UNICODE_STRING), # _UNICODE_STRING
        ("FlagGroup", c_ubyte*4),
        ("Flags", c_uint32),
        ("ObsoleteLoadCount", c_uint16),
        ("TlsIndex", c_uint16),
        ("HashLinks", LIST_ENTRY),
        ("TimeDateStamp", c_uint32),
        ("EntryPointActivationContext", c_void_p), # Ptr64 _ACTIVATION_CONTEXT
        ("Lock", c_void_p),
        ("DdagNode", c_void_p), #_LDR_DDAG_NODE
        ("NodeModuleLink", LIST_ENTRY),
        ("LoadContext", c_void_p), # _LDRP_LOAD_CONTEXT
        ("ParentDllBase", c_void_p),
        ("SwitchBackContext", c_void_p),
        ("BaseAddressIndexNode", RTL_BALANCED_NODE),
        ("MappingInfoIndexNode", RTL_BALANCED_NODE),
        ("OriginalBase", c_uint32),
        ("LoadTime", LARGE_INTEGER),
        ("BaseNameHashValue", c_uint32),
        ("LoadReason", c_uint32), # _LDR_DLL_LOAD_REASON
        ("ImplicitPathOptions", c_uint32),
        ("ReferenceCount", c_uint32),
        ("DependentLoadFlags", c_uint32),
        ("SigningLevel", c_ubyte)
    ]

class PROCESS_HEAP(Structure):
    _fields_=[
        ("Segment",c_uint64),
        ("Entry",c_uint64),
        ("SegmentSignature",c_uint32),
        ("SegmentFlags",c_uint32),
        ("SegmentListEntry",c_void_p * 2),
        ("Heap",c_void_p),
        ("BaseAddress",c_void_p),
        ("NumberOfPages",c_uint32),
        ("Padding0",c_uint32),
        ("FirstEntry",c_void_p),
        ("LastValidEntry",c_void_p),
        ("NumberOfUnCommittedPages",c_uint32),
        ("NumberOfUnCommittedRanges",c_uint32),
        ("SegmentAllocatorBackTraceIndex",c_uint16),
        ("Reserved",c_uint16),
        ("Padding1",c_uint8 * 4),
        ("UCRSegmentList",c_void_p*2),
        ("Flags",c_uint32),
        ("ForceFlags",c_uint32),
        ("CompatibilityFlags",c_uint32),
        ("EncodeFlagMask",c_uint32),
        ("Encoding",c_void_p * 2),
        ("Interceptor",c_uint32),
        ("VirtualMemoryThreshold",c_uint32),
        ("Signature",c_uint32),
        ("SegmentReserve",c_uint64),
        ("SegmentCommit",c_uint64),
        ("DeCommitFreeBlockThreshold",c_uint64),
        ("DeCommitTotalFreeThreshold",c_uint64),
        ("TotalFreeSize",c_uint64),
        ("MaximumAllocationSize",c_uint64),
        ("ProcessHeapsListIndex",c_uint16),
        ("HeaderValidateLength",c_uint16),
        ("HeaderValidateCopy",c_void_p),
        ("NextAvailableTagIndex",c_uint16),
        ("MaximumTagIndex",c_uint16),
        ("TagEntries",c_void_p),
        ("UCRList",c_void_p*2),
        ("AlignRound",c_uint64),
        ("AlignMask",c_uint64),
        ("VirtualAllocdBlocks",c_void_p*2),
        ("SegmentList",c_void_p*2),
        ("AllocatorBackTraceIndex",c_uint16),
        ("Padding2",c_uint8*2),
        ("NonDedicatedListLength",c_uint32),
        ("BlocksIndex",c_void_p),
    ]

class PEB(Structure):
    _fields_ = [
        ("InheritedAddressSpace", c_ubyte),             #+0x000
        ("ReadImageFileExecOptions", c_ubyte),          #+0x001
        ("BeingDebugged", c_ubyte),                     #+0x002
        ("BitField", c_ubyte),                          #+0x003
        ("Padding0", c_uint32),                         #+0x004
        ("Mutant", c_uint64),                           #+0x008
        ("ImageBaseAddress", c_void_p),                 #+0x010
        ("Ldr", c_void_p ),                             #+0x018
        ("ProcessParameters", c_void_p),                #+0x020
        ("SubSystemData", c_void_p),                    #+0x028
        ("ProcessHeap", c_void_p),                      #+0x030
        ("FastPebLock", c_void_p),                      #+0x038
        ("AtlThunkSListPtr", c_void_p),                 #+0x040
        ("IFEOKey", c_void_p),                          #+0x048
        ("CrossProcessFlags", c_uint32),                #+0x050
        ("Padding1", c_uint32),                         #+0x054
        ("KernelCallbackTable", c_void_p),              #+0x058
        ("SystemReserved", c_uint32),                   #+0x060
        ("AtlThunkSListPtr32", c_uint32),               #+0x064
        ("ApiSetMap", c_void_p),                        #+0x068
        ("TlsExpansionCounter", c_uint32),              #+0x070
        ("Padding2", c_uint8 * 4),                      #+0x074
        ("TlsBitmap", c_void_p),                        #+0x078
        ("TlsBitmapBits", c_uint32 * 2),                #+0x080
        ("ReadOnlySharedMemoryBase", c_void_p),         #+0x088
        ("SharedData", c_void_p),                       #+0x090  
        ("ReadOnlyStaticServerData", c_void_p),         #+0x098
        ("AnsiCodePageData", c_void_p),                 #+0x0a0
        ("OemCodePageData", c_void_p),                  #+0x0a8
        ("UnicodeCaseTableData", c_void_p),             #+0x0b0
        ("NumberOfProcessors", c_uint32),               #+0x0b8
        ("NtGlobalFlag", c_uint32),                     #+0x0bc
        ("CriticalSectionTimeout", c_void_p),           #+0x0c0
        ("HeapSegmentReserve", c_uint64),               #+0x0c8
        ("HeapSegmentCommit", c_uint64),                #+0x0d0
        ("HeapDeCommitTotalFreeThreshold", c_uint64),   #+0x0d8
        ("HeapDeCommitFreeBlockThreshold", c_uint64),   #+0x0e0
        ("NumberOfHeaps", c_uint32),                    #+0x0e8
        ("MaximumNumberOfHeaps", c_uint32),             #+0x0ec
        ("ProcessHeaps", c_void_p),                     #+0x0f0
        ("GdiSharedHandleTable", c_void_p),             #+0x0f8
        ("ProcessStarterHelper", c_void_p),             #+0x100
        ("GdiDCAttributeList", c_uint32),               #+0x108
        ("Padding3", c_uint32),                         #+0x10c
        ("LoaderLock", c_void_p),                       #+0x110
        ("OSMajorVersion", c_uint32),                   #+0x118
        ("OSMinorVersion", c_uint32),                   #+0x11c
        ("OSBuildNumber", c_uint16),                    #+0x120
        ("OSCSDVersion", c_uint16),                     #+0x122
        ("OSPlatformId", c_uint32),                     #+0x124
        ("ImageSubsystem", c_uint32),                   #+0x128
        ("ImageSubsystemMajorVersion", c_uint32),       #+0x12c
        ("ImageSubsystemMinorVersion", c_uint32),       #+0x130
        ("Padding4", c_uint8 * 4),                      #+0x134
        ("ActiveProcessAffinityMask", c_uint64),        #+0x138 
        ("GdiHandleBuffer", c_uint32 * 60),             #+0x140
        ("PostProcessInitRoutine", c_void_p),           #+0x230
        ("TlsExpansionBitmap", c_void_p),               #+0x238
        ("TlsExpansionBitmapBits", c_uint32 * 32),      #+0x240
        ("SessionId", c_uint32),                        #+0x2c0
        ("Padding5", c_uint8 * 4),                      #+0x2c4
        ("AppCompatFlags", c_void_p),                   #+0x2c8
        ("AppCompatFlagsUser", c_void_p),               #+0x2d0    
        ("pShimData", c_void_p),                        #+0x2d8
        ("AppCompatInfo", c_void_p),                    #+0x2e0
        ("CSDVersion", c_void_p * 2),                   #+0x2e8
        ("ActivationContextData", c_void_p),            #+0x2f8
        ("ProcessAssemblyStorageMap", c_void_p),        #+0x300
        ("SystemDefaultActivationContextData", c_void_p),   #+0x308
        ("SystemAssemblyStorageMap", c_void_p),         #+0x310
        ("MinimumStackCommit", c_uint64),               #+0x318
        ("SparePointers", c_void_p * 4),                #+0x320
        ("SpareUlongs", c_uint32 * 5),                  #+0x340
        ("WerRegistrationData", c_void_p),              #+0x358
        ("WerShipAssertPtr", c_void_p),                 #+0x360
        ("pUnused", c_void_p),                          #+0x368
        ("pImageHeaderHash", c_void_p),                 #+0x370
        ("TracingFlags", c_uint32),                     #+0x378
        ("Padding6", c_uint8 * 4),                      #+0x37c
        ("CsrServerReadOnlySharedMemoryBase", c_uint64),#+0x380
        ("TppWorkerpListLock", c_uint64),               #+0x388
        ("TppWorkerpList", c_void_p * 2),               #+0x390
        ("WaitOnAddressHashTable", c_void_p * 128),     #+0x3a0
        ("TelemetryCoverageHeader", c_void_p),          #+0x7a0
        ("CloudFileFlags", c_uint32),                   #+0x7a8
        ("CloudFileDiagFlags", c_uint32),               #+0x7ac
        ("PlaceholderCompatibilityMode", c_uint8),      #+0x7b0
        ("PlaceholderCompatibilityModeReserved", c_uint8 * 7),  #+0x7b1
        ("LeapSecondData", c_void_p),                   #+0x7b8
        ("LeapSecondFlags", c_uint32),                  #+0x7c0
        ("NtGlobalFlag2", c_uint32),                    #+0x7c4
    ]

class PEB_LDR_DATA(Structure):
    _fields_ = [
        ("Length", c_uint32),
        ("Initialized", c_uint32),
        ("SsHandle", c_void_p),
        ("InLoadOrderModuleList", LIST_ENTRY),
        ("InMemoryOrderModuleList", LIST_ENTRY),
        ("InInitializationOrderModuleList", LIST_ENTRY),
        ("EntryInProgress", c_void_p),
        ("ShutdownInProgress", c_void_p),
        ("ShutdownThreadId", c_void_p),
    ]


def Initpeb():
    peb = PEB()
    peb.InheritedAddressSpace = 0
    peb.ReadImageFileExecOptions = 0
    peb.BeingDebugged = 0
    peb.BitField = 4
    peb.Padding0 = 0
    peb.Mutant = -1
    peb.ImageBaseAddress = 0x140000000
    peb.Ldr= LdrBase
    peb.ProcessParameters =  ProcessHeapBase + 0x1d50# 채워줘야함
    peb.SubSystemData = 0x0
    peb.NtGlobalFlag = 0x0
    peb.ProcessHeap = ProcessHeapBase
    peb.CrossProcessFlags = 0x1
    peb.ActivationContextData = 0x400000
    return peb
 

def InitProcessHeap():
    procHeap = PROCESS_HEAP()
    procHeap.Segment = 0x0
    procHeap.Entry = 0x0 # 특정한 값으로 채워야함
    procHeap.SegmentSignature = 0xffeeffee
    procHeap.SegmentFlags = 0x2
    procHeap.BlocksIndex = ProcessHeapBase + 0x2e8
    procHeap.Flags = 0x2
    procHeap.ForceFlags = 0x0
    procHeap.pShimData = PshimDataBase
    return procHeap

'''
# ======================================================== #
# Not Used!
# We will Update After..
# ======================================================== #
'''

# def InitLdr():
#     ldr = PEB_LDR_DATA()
#     ldr.Length = 0x58
#     ldr.Initialized = 0x1
#     ldr.SsHandle = 0x0
#     ldr.InLoadOrderModuleList_Flink = 0x500000
#     ldr.InLoadOrderModuleList_Blink = 0x500000
#     ldr.InMemoryOrderModuleList_Flink = 0x500000 + 0x10
#     ldr.InMemoryOrderModuleList_Blink = 0x500000 + 0x10
#     ldr.InInitializationOrderModuleList_Flink = 0x500000 + 0x20
#     ldr.InInitializationOrderModuleList_Blink = 0x500000 + 0x20
#     ldr.EntryInProgress = 0x0
#     ldr.ShutdownInProgress = 0x0
#     ldr.ShutdownThreadId = 0x0


# def SetLdrTable(base, dllBase, Path, dll, ep, soi):
#     lt  = LDR_DATA_TABLE_ENTRY()
#     changeBase = base + 0x770
#     lt.InLoadOrderLinks.Flink = 0x500000
#     lt.InLoadOrderLinks.Blink = changeBase -0x770
#     lt.InMemoryOrderLinks.Flink = 0x500000 + 0x10
#     lt.InMemoryOrderLinks.Blink = changeBase + 0x10 -0x770
#     lt.InInitializationOrderLinks.Flink = 0x500000 + 0x20
#     lt.InInitializationOrderLinks.Blink = changeBase + 0x20 -0x770
#     # if GLOBALVAR['LoadCnt'] == 0:
#     #     lt.InLoadOrderLinks.Blink = 0x500000
#     #     lt.InMemoryOrderLinks.Blink = 0x500000 + 0x10
#     #     lt.InInitializationOrderLinks.Blink = 0x500000+ 0x20
#     #     changeBase = base
#     lt.DllBase = dllBase
#     lenPath = len(Path)*2
#     lenDll = len(dll)*2
#     try:
#         uc.mem_write(GLOBALVAR['dllNameSpace'], Path.encode('utf-16')+b'\x00\x00')
        
#     except:
#         uc.mem_map(GLOBALVAR['dllNameSpace'], 0x10000)
#         uc.mem_write(GLOBALVAR['dllNameSpace'], Path.encode('utf-16')+b'\x00\x00')
#     lt.EntryPoint = ep
#     lt.SizeOfImage = soi
#     lt.FullDllName.Length = lenPath 
#     lt.FullDllName.MaximumLength = lenDll+2
#     lt.FullDllName.Buffer = GLOBALVAR['dllNameSpace']
#     lt.BaseDllName.Length = lenDll
#     lt.BaseDllName.MaximumLength = lenDll+2
#     lt.BaseDllName.Buffer = GLOBALVAR['dllNameSpace'] + lenPath - lenDll
#     GLOBALVAR['dllNameSpace'] += lenPath + 2
#     uc.mem_write(changeBase, bytes(lt))
#     ChagnePrevNodeFLink(uc, changeBase)
#     return changeBase

# def ChagnePrevNodeFLink(uc, addr):
#     uc.mem_write(addr-0x770, struct.pack('<Q',  addr))
#     uc.mem_write(addr+0x10-0x770, struct.pack('<Q', addr+0x10))
#     uc.mem_write(addr+0x20-0x770, struct.pack('<Q', addr+0x20))