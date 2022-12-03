from unicorn import *
from unicorn.x86_const import *
from ctypes import *
from config import DLL_SETTING

Ldr = DLL_SETTING.LOADED_DLL['ntdll.dll'] + 0x17A120
PROC_HEAP_ADDRESS=0x000001E9E3850000
PEB_ADDR = 0xff20000000000000

class LIST_ENTRY(Structure):
    _fields_ =[
        ("InLoadOrderModuleList_Flink", c_void_p),
        ("InLoadOrderModuleList_Blink", c_void_p),
        ("InMemoryOrderModuleList_Flink", c_void_p ),
        ("InMemoryOrderModuleList_Blink", c_void_p ),
        ("InInitializationOrderModuleList_Flink", c_void_p ),
        ("InInitializationOrderModuleList_Blink", c_void_p ),
        ("BaseAddress", c_void_p),
        ("EntryPoint", c_void_p),

    ]

class PEB_LDR_DATA(Structure):
    _fields_ = [
        ("Length", c_uint32),
        ("Initialized", c_uint32),
        ("SsHandle", c_void_p),
        ("InLoadOrderModuleList_Flink", c_void_p),
        ("InLoadOrderModuleList_Blink", c_void_p),
        ("InMemoryOrderModuleList_Flink", c_void_p ),
        ("InMemoryOrderModuleList_Blink", c_void_p ),
        ("InInitializationOrderModuleList_Flink", c_void_p ),
        ("InInitializationOrderModuleList_Blink", c_void_p ),
        ("EntryInProgress", c_void_p),
        ("ShutdownInProgress", c_void_p),
        ("ShutdownThreadId", c_void_p),
    ]

class UNICODE_STRING(Structure):
    _fields_ = [
        ("Length", c_uint16),
        ("MaximumLength", c_uint16),
        ("Buffer", c_wchar_p)
    ]

class _LIST_ENTRY(Structure):
    _fields_ = [
        ("Flink", c_void_p),
        ("Blink", c_void_p)
    ]

class _RTL_BALANCED_NODE(Structure):
    _fields_=[
        ("Left", c_void_p),
        ("Right", c_void_p),
        ("ParentValue", c_uint64)
    ]

class _LARGE_INTEGER(Structure):
    _fields_=[
        ("LowPart", c_uint32),
        ("HighPart", c_int32),
    ]
class LDR_DATA_TABLE_ENTRY(Structure):
    _fields_ = [
        ("InLoadOrderLinks", _LIST_ENTRY),
        ("InMemoryOrderLinks", _LIST_ENTRY),
        ("InInitializationOrderLinks", _LIST_ENTRY),
        ("DllBase", c_void_p),
        ("EntryPoint", c_void_p),
        ("SizeOfImage", c_uint32),
        ("FullDllName", UNICODE_STRING), # _UNICODE_STRING
        ("BaseDllName", UNICODE_STRING), # _UNICODE_STRING
        ("FlagGroup", c_ubyte*4),
        ("Flags", c_uint32),
        ("ObsoleteLoadCount", c_uint16),
        ("TlsIndex", c_uint16),
        ("HashLinks", _LIST_ENTRY),
        ("TimeDateStamp", c_uint32),
        ("EntryPointActivationContext", c_void_p), # Ptr64 _ACTIVATION_CONTEXT
        ("Lock", c_void_p),
        ("DdagNode", c_void_p), #_LDR_DDAG_NODE
        ("NodeModuleLink", _LIST_ENTRY),
        ("LoadContext", c_void_p), # _LDRP_LOAD_CONTEXT
        ("ParentDllBase", c_void_p),
        ("SwitchBackContext", c_void_p),
        ("BaseAddressIndexNode", _RTL_BALANCED_NODE),
        ("MappingInfoIndexNode", _RTL_BALANCED_NODE),
        ("OriginalBase", c_uint32),
        ("LoadTime", _LARGE_INTEGER),
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
        ("InheritedAddressSpace", c_ubyte),
        ("ReadImageFileExecOptions", c_ubyte),
        ("BeingDebugged", c_ubyte),
        ("BitField", c_ubyte),
        ("Padding0", c_uint32),
        ("Mutant", c_uint64),
        ("ImageBaseAddress", c_void_p),
        ("Ldr", c_void_p ),
        ("ProcessParameters", c_void_p),
        ("SubSystemData", c_void_p),
        ("ProcessHeap", c_void_p),
        ("FastPebLock", c_void_p),
        ("AtlThunkSListPtr", c_void_p),
        ("IFEOKey", c_void_p),
        ("CrossProcessFlags", c_uint32),
        ("Padding1", c_uint32),
        ("KernelCallbackTable", c_void_p),
        ("SystemReserved", c_uint32),
        ("AtlThunkSListPtr32", c_uint32),
        ("ApiSetMap", c_void_p),
        ("TlsExpansionCounter", c_uint32),
        ("Padding2", c_uint8 * 4),
        ("TlsBitmap", c_void_p),
        ("TlsBitmapBits", c_uint32 * 2),
        ("ReadOnlySharedMemoryBase", c_void_p),
        ("SharedData", c_void_p),
        ("ReadOnlyStaticServerData", c_void_p),
        ("AnsiCodePageData", c_void_p),
        ("OemCodePageData", c_void_p),
        ("UnicodeCaseTableData", c_void_p),
        ("NumberOfProcessors", c_uint32),
        ("NtGlobalFlag", c_uint32),
        ("CriticalSectionTimeout", c_void_p),
        ("HeapSegmentReserve", c_uint64),
        ("HeapSegmentCommit", c_uint64),
        ("HeapDeCommitTotalFreeThreshold", c_uint64),
        ("HeapDeCommitFreeBlockThreshold", c_uint64),
        ("NumberOfHeaps", c_uint32),
        ("MaximumNumberOfHeaps", c_uint32),
        ("ProcessHeaps", c_void_p),
        ("GdiSharedHandleTable", c_void_p),
        ("ProcessStarterHelper", c_void_p),
        ("GdiDCAttributeList", c_uint32),
        ("Padding3", c_uint32),
        ("LoaderLock", c_void_p),
        ("OSMajorVersion", c_uint32),
        ("OSMinorVersion", c_uint32),
        ("OSBuildNumber", c_uint16),
        ("OSCSDVersion", c_uint16),
        ("OSPlatformId", c_uint32),
        ("ImageSubsystem", c_uint32),
        ("ImageSubsystemMajorVersion", c_uint32),
        ("ImageSubsystemMinorVersion", c_uint32),
        ("Padding4", c_uint8 * 4),
        ("ActiveProcessAffinityMask", c_uint64),
        ("GdiHandleBuffer", c_uint32 * 60),
        ("PostProcessInitRoutine", c_void_p),
        ("TlsExpansionBitmap", c_void_p),
        ("TlsExpansionBitmapBits", c_uint32 * 32),
        ("SessionId", c_uint32),
        ("Padding5", c_uint8 * 4),
        ("AppCompatFlags", c_void_p),
        ("AppCompatFlagsUser", c_void_p),
        ("pShimData", c_void_p),
        ("AppCompatInfo", c_void_p),
        ("CSDVersion", c_void_p * 2),
        ("ActivationContextData", c_void_p),
        ("ProcessAssemblyStorageMap", c_void_p),
        ("SystemDefaultActivationContextData", c_void_p),
        ("SystemAssemblyStorageMap", c_void_p),
        ("MinimumStackCommit", c_uint64),
        ("SparePointers", c_void_p * 4),
        ("SpareUlongs", c_uint32 * 5),
        ("WerRegistrationData", c_void_p),
        ("WerShipAssertPtr", c_void_p),
        ("pUnused", c_void_p),
        ("pImageHeaderHash", c_void_p),
        ("TracingFlags", c_uint32),
        ("Padding6", c_uint8 * 4),
        ("CsrServerReadOnlySharedMemoryBase", c_uint64),
        ("TppWorkerpListLock", c_uint64),
        ("TppWorkerpList", c_void_p * 2),
        ("WaitOnAddressHashTable", c_void_p * 128),
        ("TelemetryCoverageHeader", c_void_p),
        ("CloudFileFlags", c_uint32),
        ("CloudFileDiagFlags", c_uint32),
        ("PlaceholderCompatibilityMode", c_uint8),
        ("PlaceholderCompatibilityModeReserved", c_uint8 * 7),
        ("LeapSecondData", c_void_p),
        ("LeapSecondFlags", c_uint32),
        ("NtGlobalFlag2", c_uint32),
    ]

def SetPEB(uc):
    peb = PEB()
    peb.InheritedAddressSpace=0
    peb.ReadImageFileExecOptions=0
    peb.BeingDebugged=0
    peb.BitField=4
    peb.Padding0=0
    peb.Mutant=-1
    peb.ImageBaseAddress=0x140000000
    peb.Ldr= Ldr
    peb.ProcessParameters =  PROC_HEAP_ADDRESS+0x1d50# 채워줘야함
    peb.SubSystemData = 0x0
    peb.ProcessHeap=PROC_HEAP_ADDRESS
    peb.ActivationContextData = 0x400000 # 언팩시 필요 일단 스택 사이즈를 줘봄
    uc.mem_write(PEB_ADDR ,bytes(peb))



def SetListEntry(uc, baseaddress, number):
    listEntry = LIST_ENTRY()
    listEntry.InLoadOrderModuleList_Flink = (Ldr + 0x60) + (number+1)*0x40 
    listEntry.InMemoryOrderModuleList_Flink = (Ldr + 0x60) + (number+1)*0x40 +0x10 
    listEntry.InInitializationOrderModuleList_Flink = (Ldr + 0x60) + (number+1)*0x40 +0x20 
    listEntry.InLoadOrderModuleList_Blink = (Ldr + 0x60) + (number-1)*0x40
    listEntry.InMemoryOrderModuleList_Blink = (Ldr + 0x60) + (number-1)*0x40 +0x10
    listEntry.InInitializationOrderModuleList_Blink = (Ldr + 0x60) + (number-1)*0x40 +0x20
    listEntry.BaseAddress = baseaddress
    listEntry.EntryPoint = 0
    uc.mem_write((Ldr+0x60) + (number)*0x40,bytes(listEntry))
    #print("BaseAddress : ",hex(listEntry.BaseAddress))

def InitLdr(uc):
    ldr = PEB_LDR_DATA()
    ldr.Length = 0x58
    ldr.Initialized = 0x1
    ldr.SsHandle = 0x0
    ldr.InLoadOrderModuleList_Flink = Ldr + 0x60
    ldr.InLoadOrderModuleList_Blink = 0x0
    ldr.InMemoryOrderModuleList_Flink = Ldr + 0x70 
    ldr.InMemoryOrderModuleList_Blink = 0x0
    ldr.InInitializationOrderModuleList_Flink = Ldr+0x80 
    ldr.InInitializationOrderModuleList_Blink = 0x0
    ldr.EntryInProgress = 0x0
    ldr.ShutdownInProgress = 0x0
    ldr.ShutdownThreadId = 0x0
    uc.mem_write(Ldr ,bytes(ldr))
    

def SetProcessHeap(uc):
    procHeap = PROCESS_HEAP()
    procHeap.Segment = 0x0
    procHeap.Entry = 0x0 # 특정한 값으로 채워야함
    procHeap.SegmentSignature = 0xffeeffee
    procHeap.SegmentFlags = 0x2
    procHeap.BlocksIndex = PROC_HEAP_ADDRESS+0x2e8
    uc.mem_write(PROC_HEAP_ADDRESS ,bytes(procHeap))
