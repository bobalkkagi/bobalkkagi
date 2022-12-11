from ctypes import *
from .constValue import TebBase, PebBase, StackBase, StackLimit


class LIST_ENTRY(Structure):
    _fields_ = [
        ("Flink", c_void_p),
        ("Blink", c_void_p)
    ]

class NtTib(Structure):
    _fields_ = [
        ("ExceptionList", c_void_p),        #[+0x000]
        ("StackBase", c_void_p),            #[+0x008]
        ("StackLimit", c_void_p),           #[+0x010]
        ("SubSystemTib", c_void_p),         #[+0x018]
        ("FiberData", c_void_p),            #[+0x020] #Version [Type: unsigned long]
        ("ArbitraryUserPointer", c_void_p), #[+0x028]
        ("AddrOfTEB", c_void_p)                  #[+0x030]
    ]

class ClientId(Structure):
    _fields_ = [
        ("UniqueProcess", c_void_p),#[+0x000]
        ("UniqueThread", c_void_p), #[+0x008]  
    ]

class ActivationStack(Structure):
    _fields_ = [
        ("ActiveFrame", c_void_p),              #[+0x000]
        ("FrameListCache", LIST_ENTRY),         #[+0x008]
        ("Flags", c_uint32),                    #[+0x018]
        ("NextCookieSequenceNumber", c_uint32), #[+0x01c]
        ("StackId", c_uint32),                  #[+0x020]
    ]
class GdiTebBatch(Structure):
    _fields_ = [
        ("Offset", c_uint32,31),                #[+0x000]
        ("HasRenderingCommand", c_uint32,1),    #[+0x000]                
        ("HDC", c_uint64),                      #[+0x008]
        ("Buffer", c_uint*310)                  #[+0x010]
    ]

class UNICODE_STRING(Structure):
    _fields_ = [
        ("Length", c_uint16),           #[+0x000]
        ("MaximumLength", c_uint16),    #[+0x002]
        ("Buffer", c_wchar_p)           #[+0x008]
    ]

class GUID(Structure):
    _fields_ = [
        ("Data1", c_uint32),    #+0x000 
        ("Data2", c_uint16),    #+0x004 
        ("Data3", c_uint16),    #+0x006 
        ("Data4", c_ubyte*8)    #+0x008 
    ]

class SameTebFlags(Structure):
    _fields_ = [
        ("SafeThunkCall", c_uint16, 1),         #+0x17ee : Pos 0, 1 Bit
        ("InDebugPrint", c_uint16, 1),          #+0x17ee : Pos 1, 1 Bit
        ("HasFiberData", c_uint16, 1),          #+0x17ee : Pos 2, 1 Bit
        ("SkipThreadAttach", c_uint16, 1),      #+0x17ee : Pos 3, 1 Bit
        ("WerInShipAssertCode", c_uint16, 1),   #+0x17ee : Pos 4, 1 Bit
        ("RanProcessInit", c_uint16, 1),        #+0x17ee : Pos 5, 1 Bit
        ("ClonedThread", c_uint16, 1),          #+0x17ee : Pos 6, 1 Bit
        ("SuppressDebugMsg", c_uint16, 1),      #+0x17ee : Pos 7, 1 Bit
        ("DisableUserStackWalk", c_uint16, 1),  #+0x17ee : Pos 8, 1 Bit
        ("RtlExceptionAttached", c_uint16, 1),  #+0x17ee : Pos 9, 1 Bit
        ("InitialThread", c_uint16, 1),         #+0x17ee : Pos 10, 1 Bit
        ("SessionAware", c_uint16, 1),          #+0x17ee : Pos 11, 1 Bit
        ("LoadOwner", c_uint16, 1),             #+0x17ee : Pos 12, 1 Bit
        ("LoaderWorker", c_uint16, 1),          #+0x17ee : Pos 13, 1 Bit
        ("SkipLoaderInit", c_uint16, 1),        #+0x17ee : Pos 14, 1 Bit
        ("SkipFileAPIBrokering", c_uint16, 1),  #+0x17ee : Pos 15, 1 Bit
    ]

class TEB(Structure):
    _fields_ = [
        ("NtTib" , NtTib),                                      #+0x000
        ("EnvironmentPointer", c_void_p),                       #+0x038  
        ("ClientId", ClientId),                                 #+0x040   
        ("ActiveRpcHandle", c_void_p),                          #+0x050
        ("ThreadLocalStoragePointer", c_void_p),                #+0x058
        ("ProcessEnvironmentBlock", c_void_p),                  #+0x060      
        ("LastErrorValue", c_uint32),                           #+0x068       
        ("countOfOwnedCriticalSections", c_uint32),             #+0x06c
        ("CsrClientThread", c_void_p),                          #+0x070
        ("Win32ThreadInfo", c_void_p),                          #+0x078
        ("User32Reserved", c_uint32*26),                        #+0x080
        ("UserReserved", c_uint32*5),                           #+0x0e8
        ("WOW32Reserved", c_void_p),                            #+0x100
        ("CurrentLocale", c_uint32),                            #+0x108
        ("FpSoftwareStatusRegister", c_uint32),                 #+0x10c
        ("ReservedForDebuggerInstrumentation", c_void_p*16),    #+0x110 
        ("SystemReserved1", c_void_p*30),                       #+0x190 
        ("PlaceholderCompatibilityMode", c_char),               #+0x280
        ("PlaceholderHydrationAlwaysExplicit", c_ubyte),        #+0x281
        ("PlaceholderReserved", c_char*10),                     #+0x282
        ("ProxiedProcessId",  c_uint32),                        #+0x28c
        ("ActivationStack", ActivationStack),                   #+0x290
        ("WorkingOnBehalfTicket", c_ubyte*8),                   #+0x2b8 
        ("ExceptionCode", c_int32),                             #+0x2c0
        ("Padding0", c_ubyte*4),                                #+0x2c4
        ("ActivationContextStackPointer", c_void_p),            #+0x2c8
        ("InstrumentationCallbackSp", c_uint64),                #+0x2d0
        ("InstrumentationCallbackPreviousPc", c_uint64),        #+0x2d8
        ("InstrumentationCallbackPreviousSp", c_uint64),        #+0x2e0
        ("TxFsContext", c_uint32),                              #+0x2e8
        ("InstrumentationCallbackDisabled", c_ubyte),           #+0x2ec
        ("UnalignedLoadStoreExceptions", c_ubyte),              #+0x2ed
        ("Padding1", c_ubyte*2),                                #+0x2ee
        ("GdiTebBatch", GdiTebBatch),                           #+0x2f0
        ("RealClientId", ClientId),                             #+0x7d8
        ("GdiCachedProcessHandle", c_void_p),                   #+0x7e8
        ("GdiClientPID", c_uint32),                             #+0x7f0
        ("GdiClientTID", c_uint32),                             #+0x7f4
        ("GdiThreadLocalInfo", c_void_p),                       #+0x7f8
        ("Win32ClientInfo", c_uint64*62),                       #+0x800
        ("glDispatchTable", c_void_p*233),                      #+0x9f0
        ("glReserved1", c_uint64*29),                           #+0x1138
        ("glReserved2", c_void_p),                              #+0x1220
        ("glSectionInfo", c_void_p),                            #+0x1228
        ("glSection", c_void_p),                                #+0x1230
        ("glTable", c_void_p),                                  #+0x1238
        ("glCurrentRC", c_void_p),                              #+0x1240
        ("glContext", c_void_p),                                #+0x1248
        ("LastStatusValue", c_uint32),                          #+0x1250
        ("Padding2", c_ubyte*4),                                #+0x1254
        ("StaticUnicodeString", UNICODE_STRING),                #+0x1258 
        ("StaticUnicodeBuffer", c_wchar*261),                   #+0x1268
        ("Padding3", c_ubyte*6),                                #+0x1472
        ("DeallocationStack", c_void_p),                        #+0x1478
        ("TlsSlots", c_void_p*64),                              #+0x1480
        ("TlsLinks", LIST_ENTRY),                               #+0x1680 
        ("Vdm", c_void_p),                                      #+0x1690
        ("ReservedForNtRpc", c_void_p),                         #+0x1698
        ("DbgSsReserved", c_void_p*2),                          #+0x16a0
        ("HardErrorMode", c_uint32),                            #+0x16b0
        ("Padding4", c_ubyte*4),                                #+0x16b4
        ("Instrumentation", c_void_p*11),                       #+0x16b8
        ("ActivityId", GUID),                                   #+0x1710
        ("SubProcessTag", c_void_p),                            #+0x1720
        ("PerflibData", c_void_p),                              #+0x1728
        ("EtwTraceData", c_void_p),                             #+0x1730
        ("WinSockData", c_void_p),                              #+0x1738
        ("GdiBatchCount", c_uint32),                            #+0x1740
        ("IdealProcessorValue", c_uint32),                      #+0x1744
        ("GuaranteedStackBytes", c_uint32),                     #+0x1748
        ("Padding5", c_ubyte*4),                                #+0x174c
        ("ReservedForPerf", c_void_p),                          #+0x1750
        ("ReservedForOle", c_void_p),                           #+0x1758
        ("WaitingOnLoaderLock", c_uint32),                      #+0x1760
        ("Padding6", c_ubyte*4),                                #+0x1764
        ("SavedPriorityState", c_void_p),                       #+0x1768
        ("ReservedForCodeCoverage", c_uint64),                  #+0x1770
        ("ThreadPoolData", c_void_p),                           #+0x1778
        ("TlsExpansionSlots", c_void_p),                        #+0x1780 
        ("DeallocationBStore", c_void_p),                       #+0x1788 
        ("BStoreLimit", c_void_p),                              #+0x1790
        ("MuiGeneration",c_uint32),                             #+0x1798
        ("IsImpersonating",c_uint32),                           #+0x179c
        ("NlsCache", c_void_p),                                 #+0x17a0
        ("pShimData", c_void_p),                                #+0x17a8
        ("HeapData", c_uint32),                                 #+0x17b0
        ("Padding7", c_ubyte*4),                                #+0x17b4
        ("CurrentTransactionHandle", c_void_p),                 #+0x17b8
        ("ActiveFrame", c_void_p),                              #+0x17c0
        ("FlsData", c_void_p),                                  #+0x17c8
        ("PreferredLanguages", c_void_p),                       #+0x17d0
        ("UserPrefLanguages", c_void_p),                        #+0x17d8
        ("MergedPrefLanguages", c_void_p),                      #+0x17e0
        ("MuiImpersonation", c_uint32),                         #+0x17e8
        ("CrossTebFlags", c_uint16),                            #+0x17ec  
        ("SameTebFlags", SameTebFlags),                         #+0x17ee
        ("TxnScopeEnterCallback", c_void_p),                    #+0x17f0
        ("TxnScopeExitCallback", c_void_p),                     #+0x17f8
        ("TxnScopeContext", c_void_p),                          #+0x1800
        ("LockCount", c_uint32),                                #+0x1808
        ("WowTebOffset", c_int32),                              #+0x180c
        ("ResourceRetValue", c_void_p),                         #+0x1810
        ("ReservedForWdf", c_void_p),                           #+0x1818
        ("ReservedForCrt", c_uint64),                           #+0x1820
        ("EffectiveContainerId", GUID),                         #+0x1828
    ]




def InitTeb():
    teb = TEB()
    teb.NtTib.ExceptionList = -1    #Important
    teb.NtTib.StackBase = StackBase
    teb.NtTib.StackLimit = StackLimit
    teb.NtTib.AddrOfTEB = TebBase
    #teb.ClientId_UniqueProcess = pid
    #teb.ClientId_UniqueThread = pid+0x4
    teb.ProcessEnvironmentBlock = PebBase
    #teb.Win32ThreadInfo =0xd30
    #teb.CurrentLocale =0x412
    #teb.ActivationStack.FrameListCache.Flink = TEB_BASE+0x298
    #teb.ActivationStack.FrameListCache.Blink = TEB_BASE+0x298
    #teb.ActivationStack.Flags = 0x2
    #teb.ActivationStack.NextCookieSequenceNumber = 0x1
    #teb.ActivationStack.StackId = 0x2147dee
    #teb.ActivationContextStackPointer = TEB_BASE+0x290
    #teb.TxFsContext = 0xfffe
    #teb.GdiTebBatch.HDC = 0x160000
    #teb.RealClientId.UniqueProcess = pid
    #teb.RealClientId.UniqueThread = pid+0x4
    #teb.StaticUnicodeString.Length = 0x0
    #teb.StaticUnicodeString.MaximumLength = 0x20a
    #teb.StaticUnicodeString.Buffer = TEB_BASE+0x1268
    #teb.StaticUnicodeBuffer = u'ntdll.dll'
    #teb.IdealProcessorValue = 0x2020000
    #teb.SameTebFlags.RanProcessInit = 1
    #teb.SameTebFlags.InitialThread = 1
    #teb.SameTebFlags.LoadOwner = 1

    return teb
   
