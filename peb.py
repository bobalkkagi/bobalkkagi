from unicorn import *
from unicorn.x86_const import *
from ctypes import *
from config import DLL_SETTING

Ldr = 0x000001B54C810000
#Ldr = 0x000001B54C810040
#Ldr = 0x000001B54C810080


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
        
        # ... too much item
    ]


peb = PEB()
peb .InheritedAddressSpace=0
peb.ReadImageFileExecOptions=0
peb.BeingDebugged=0
peb.BitField=4
peb.Padding0=0
peb.Mutant=-1
peb.ImageBaseAddress=0x140000000
peb.Ldr= 0x2

ldr = PEB_LDR_DATA()

ldr.Length = 3
peb.Ldr=id(ldr)

print(hex(peb.Ldr))



peb_ldr_data=PEB_LDR_DATA()

peb_ldr_data.Length = 0x58
peb_ldr_data.Initialized = 0x1
peb_ldr_data.SsHandle = 0x0

def SetListEntry(uc, dllName,number):
    listEntry = LIST_ENTRY()
    listEntry.InLoadOrderModuleList_Flink = Ldr + (number+1)*0x40 
    listEntry.InLoadOrderModuleList_Blink = Ldr + (number-1)*0x40
    listEntry.InMemoryOrderModuleList_Flink = Ldr + (number+1)*0x40 +0x10 
    listEntry.InMemoryOrderModuleList_Blink = Ldr + (number-1)*0x40 +0x10
    listEntry.InInitializationOrderModuleList_Flink = Ldr + (number+1)*0x40 +0x20 
    listEntry.InInitializationOrderModuleList_Blink = Ldr + (number-1)*0x40 +0x20
    listEntry.BaseAddress = DLL_SETTING.LOADED_DLL[dllName]
    listEntry.EntryPoint = 0
    uc.mem_write(Ldr + (number)*0x40,bytes(listEntry))
    #print("BaseAddress : ",hex(listEntry.BaseAddress))

def SetLdr(uc):
    ldr = PEB_LDR_DATA()