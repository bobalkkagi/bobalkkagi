from ctypes import *

class TEB(Structure):
    _fields_ = [
    # NT_TIB < 0x38
    ("ExceptionList" , c_void_p),                            #+0x000 Ptr64 _EXCEPTION_REGISTRATION_RECORD
    ("StackBase", c_void_p),                                 #+0x008
    ("StackLimit", c_void_p),                                #+0x010
    ("SubSystemTib", c_void_p),                              #+0x018
    ("FiberData", c_void_p),                                 #+0x020 datatype union with version(Uint4B) 
    ("ArbitaryUserPointer", c_void_p),                       #+0x028
    ("AddrOfTeb", c_void_p),                                 #+0x030
    ("EnvironmentPointer", c_void_p),                        #+0x038  
    ("ClientId_UniqueProcess", c_void_p),                    #+0x040       ClientId
    ("ClientId_UniqueThread", c_void_p),                     #+0x048
    ("ActiveRpcHandle", c_void_p),                           #+0x050
    ("ThreadLocalStoragePointer", c_void_p),                 #+0x058
    ("ProcessEnvironmentBlock", c_void_p),                   #+0x060       Ptr64 _PEB
    ("LastErrorValue", c_uint32),                            #+0x068       Uint4B
    ("countOfOwnedCriticalSections", c_uint32),              #+0x06c
    ("CsrClientThread", c_void_p),                           #+0x070
    ("Win32ThreadInfo", c_void_p),                           #+0x078
    ("User32Reserved", c_uint32*26),                         #+0x080
    ("UserReserved", c_uint32*5),                            #+0x0e8 [5] Uint4B
    ("WOW32Reserved", c_void_p),                             #+0x100
    ("CurrentLocale", c_uint32),                             #+0x108
    ("FpSoftwareStatusRegister", c_uint32),                  #+0x10c
    ("ReservedForDebuggerInstrumentation", c_void_p*16),     #+0x110 [16] Ptr64 Void
    ("SystemReserved1", c_void_p*30),                        #+0x190 [30] Ptr64 Void
    ("PlaceholderCompatibilityMode", c_char),                #+0x280
    ("PlaceholderHydrationAlwaysExplicit", c_ubyte),         #+0x281
    ("PlaceholderReserved", c_char*10),                      #+0x282 [10] Char
    ("ProxiedProcessId",  c_uint32),                         #+0x28c
    ("ActiveFrame", c_void_p),                               #+0x290 _ActivationStack  : _ACTIVATION_CONTEXT_STACK
    ("FrameListCache_Flink", c_void_p),                      #       rameListCache     : Ptr64 _LIST_ENTRY
    ("FrameListCache_Blink", c_void_p),                      #       Ptr64 _LIST_ENTRY
    ("Flags", c_uint32),
    ("NextCookieSequenceNumber", c_uint32),
    ("StackId", c_uint32),
    ("WorkingOnBehalfTicket", c_ubyte*8),                    #+0x2b8 [8] UChar
    ("ExceptionCode", c_int32),                              #+0x2c0
    ("Padding0", c_ubyte*4),                                 #+0x2c4 [4] UChar
    ("ActivationContextStackPointer", c_void_p),             #+0x2c8 Ptr64 _ACTIVATION_CONTEXT_STACK
    ("InstrumentationCallbackSp", c_uint64),                 #+0x2d0
    ("InstrumentationCallbackPreviousPc", c_uint64),         #+0x2d8
    ("InstrumentationCallbackPreviousSp", c_uint64),         #+0x2e0
    ("TxFsContext", c_uint32),                               #+0x2e8
    ("InstrumentationCallbackDisabled", c_ubyte),            #+0x2ec
    ("UnalignedLoadStoreExceptions", c_ubyte),               #+0x2ed
    ("Padding1", c_ubyte*2),                                 #+0x2ee [2] UChar
    #_GDI_TEB_BATCH
    ("GTB_Offset", c_uint32,31),                                #+0x2f0  
    ("GTB_HasRenderingCommand", c_uint32,1),                    
    ("GTB_HDC", c_uint64),
    ("GTB_Buffer", c_uint*310),                                 #        [310] Uint4B
    #--------------
    ("RealClientId_UniqueProcess", c_void_p),                #+0x7d8  RealClientId
    ("RealClientId_UniqueThread", c_void_p),
    ("GdiCachedProcessHandle", c_void_p),                    #+0x7e8
    ("GdiClientPID", c_uint32),                              #+0x7f0
    ("GdiClientTID", c_uint32),                              #+0x7f4
    ("GdiThreadLocalInfo", c_void_p),                        #+0x7f8
    ("Win32ClientInfo", c_uint64*62),                        #+0x800  [62] Uint8B
    ("glDispatchTable", c_void_p*233),                       #+0x9f0  [233] Ptr64 Void
    ("glReserved1", c_uint64*29),                            #+0x1138 [29] Uint8B
    ("glReserved2", c_void_p),                               #+0x1220
    ("glSectionInfo", c_void_p),                             #+0x1228
    ("glSection", c_void_p),                                 #+0x1230
    ("glTable", c_void_p),                                   #+0x1238
    ("glCurrentRC", c_void_p),                               #+0x1240
    ("glContext", c_void_p),                                 #+0x1248
    ("LastStatusValue", c_uint32),                           #+0x1250
    ("Padding2", c_ubyte*4),                                 #+0x1254 [4] UChar
    ("Length", c_uint16),                                    #+0x1258 StaticUnicodeString : _UNICODE_STRING
    ("MaximumLength", c_uint16),
    ("Buffer", c_uint64),                                    #        Ptr64 Wchar
    ("StaticUnicodeBuffer", c_wchar*261),                    #+0x1268 [261] Wchar
    ("Padding3", c_ubyte*6),                                 #+0x1472 [6] UChar
    ("DeallocationStack", c_void_p),                         #+0x1478
    ("TlsSlots", c_void_p*64),                               #+0x1480 [64] Ptr64 Void
    ("TlsLinks_Flink", c_void_p),                            #+0x1680 _LIST_ENTRY
    ("TlsLinks_Blink", c_void_p),
    ("Vdm", c_void_p),                                       #+0x1690
    ("ReservedForNtRpc", c_void_p),                          #+0x1698
    ("DbgSsReserved", c_void_p*2),                           #+0x16a0 [2] Ptr64 Void
    ("HardErrorMode", c_uint32),                             #+0x16b0
    ("Padding4", c_ubyte*4),                                 #+0x16b4 [4] UChar
    ("Instrumentation", c_void_p*11),                        #+0x16b8 [11] Ptr64 Void
    ("GUID_1", c_uint32),                                    #+0x1710 ActivityId : _GUID      +0x000 Data1            : Uint4B
    ("GUID_2", c_uint16),                                    #                                +0x004 Data2            : Uint2B
    ("GUID_3", c_uint16),                                    #                                +0x006 Data3            : Uint2B
    ("GUID_4", c_ubyte*8),                                   #                                +0x008 Data4            : [8] UChar
    ("SubProcessTag", c_void_p),                             #+0x1720
    ("PerflibData", c_void_p),                               #+0x1728
    ("EtwTraceData", c_void_p),                              #+0x1730
    ("WinSockData", c_void_p),                               #+0x1738
    ("GdiBatchCount", c_uint32),                             #+0x1740
    ("CurrentIdealProcessor_Group", c_uint16),               #+0x1744   _PROCESSOR_NUMBER      Group            : Uint2B
    ("CurrentIdealProcessor_Number", c_ubyte),               #+0x002                           Number           : UChar
    ("CurrentIdealProcessor_Reserved", c_ubyte),             #+0x003                           Reserved         : UChar
    ("IdealProcessorValue", c_uint32),                       #+0x1744
    ("ReservedPad0", c_ubyte),                               #+0x1744
    ("ReservedPad1", c_ubyte),                               #+0x1745
    ("ReservedPad2", c_ubyte),                               #+0x1746
    ("IdealProcessor", c_ubyte),                             #+0x1747
    ("GuaranteedStackBytes", c_uint32),                      #+0x1748
    ("Padding5", c_ubyte*4),                                 #+0x174c [4] UChar
    ("ReservedForPerf", c_void_p),                           #+0x1750
    ("ReservedForOle", c_void_p),                            #+0x1758
    ("WaitingOnLoaderLock", c_uint32),                       #+0x1760
    ("Padding6", c_ubyte*4),                                 #+0x1764 [4] UChar
    ("SavedPriorityState", c_void_p),                        #+0x1768
    ("ReservedForCodeCoverage", c_uint64),                   #+0x1770
    ("ThreadPoolData", c_void_p),                            #+0x1778
    ("TlsExpansionSlots", c_void_p),                         #+0x1780 Ptr64 Ptr64 Void
    ("ChpeV2CpuAreaInfo", c_void_p),                         #+0x1788 Ptr64 _CHPEV2_CPUAREA_INFO
    ("Unused", c_void_p),                                    #+0x1790
    ("MuiGeneration",c_uint32),                              #+0x1798
    ("IsImpersonating",c_uint32),                            #+0x179c
    ("NlsCache", c_void_p),                                  #+0x17a0
    ("pShimData", c_void_p),                                 #+0x17a8
    ("HeapData", c_uint32),                                  #+0x17b0
    ("Padding7", c_ubyte*4),                                 #+0x17b4 [4] UChar
    ("CurrentTransactionHandle", c_void_p),                  #+0x17b8
    ("ActiveFrame", c_void_p),                               #+0x17c0 Ptr64 _TEB_ACTIVE_FRAME
    ("FlsData", c_void_p),                                   #+0x17c8
    ("PreferredLanguages", c_void_p),                        #+0x17d0
    ("UserPrefLanguages", c_void_p),                         #+0x17d8
    ("MergedPrefLanguages", c_void_p),                       #+0x17e0
    ("MuiImpersonation", c_uint32),                          #+0x17e8
    ("CrossTebFlags", c_uint16),                             #+0x17ec SpareCrossTebBits : Pos 0, 16 Bits
    # "SameTebFlags" #+0x17ee   
    ("SafeThunkCall", c_uint16, 1),                          #+0x17ee : Pos 0, 1 Bit
    ("InDebugPrint", c_uint16, 1),                           #+0x17ee : Pos 1, 1 Bit
    ("HasFiberData", c_uint16, 1),                           #+0x17ee : Pos 2, 1 Bit
    ("SkipThreadAttach", c_uint16, 1),                       #+0x17ee : Pos 3, 1 Bit
    ("WerInShipAssertCode", c_uint16, 1),                    #+0x17ee : Pos 4, 1 Bit
    ("RanProcessInit", c_uint16, 1),                         #+0x17ee : Pos 5, 1 Bit
    ("ClonedThread", c_uint16, 1),                           #+0x17ee : Pos 6, 1 Bit
    ("SuppressDebugMsg", c_uint16, 1),                       #+0x17ee : Pos 7, 1 Bit
    ("DisableUserStackWalk", c_uint16, 1),                   #+0x17ee : Pos 8, 1 Bit
    ("RtlExceptionAttached", c_uint16, 1),                   #+0x17ee : Pos 9, 1 Bit
    ("InitialThread", c_uint16, 1),                          #+0x17ee : Pos 10, 1 Bit
    ("SessionAware", c_uint16, 1),                           #+0x17ee : Pos 11, 1 Bit
    ("LoadOwner", c_uint16, 1),                              #+0x17ee : Pos 12, 1 Bit
    ("LoaderWorker", c_uint16, 1),                           #+0x17ee : Pos 13, 1 Bit
    ("SkipLoaderInit", c_uint16, 1),                         #+0x17ee : Pos 14, 1 Bit
    ("SkipFileAPIBrokering", c_uint16, 1),                   #+0x17ee : Pos 15, 1 Bit
    ("TxnScopeEnterCallback", c_void_p),                     #+0x17f0
    ("TxnScopeExitCallback", c_void_p),                      #+0x17f8
    ("TxnScopeContext", c_void_p),                           #+0x1800
    ("LockCount", c_uint32),                                 #+0x1808
    ("WowTebOffset", c_int32),                               #+0x180c
    ("ResourceRetValue", c_void_p),                          #+0x1810
    ("ReservedForWdf", c_void_p),                            #+0x1818
    ("ReservedForCrt", c_uint64),                            #+0x1820
    ("EffectiveContainerId_Data1", c_uint32),                #+0x1828
    ("EffectiveContainerId_Data2", c_uint16),
    ("EffectiveContainerId_Data3", c_uint16),
    ("EffectiveContainerId_Data4", c_byte*8),
    ("LastSleepCounter", c_uint64),                          #+0x1838
    ("SpinCallCount", c_uint32),                             #+0x1840
    ("Padding8", c_ubyte*4),                                 #+0x1844 [4] UChar
    ("ExtendedFeatureDisableMask", c_uint64),                #+0x1848
    ]

class _LIST_ENTRY(Structure):
    _fields_ = [
        ("Flink", c_uint64),
        ("Blink", c_uint64)
    ]



#STACK_BASE=0x201000
#STACK_LIMIT= 0x100000
#MB = 2**20 #Mega Byte
def InitTeb():
    TEB_BASE = 0xff10000000000000
    teb = TEB(
        -1,                 #Exceptionlist         
        0x201000,           #StackBase
        0x100000,           #STackLimit
        0,                  #SubSystemTib
        0,                  #FiberData
        0,                  #ArbitaryUserPointer
        0xff10000000000000, #AddrOfTeb -> important
        0,                  #EnvironmentPointer
        0x13013,            #ClientId_UniqueProcess
        0x13018,            #ClientId_UniqueThread
        0,                  #ActiveRpcHandle
        0,                  #ThreadLocalStoragePointer
        0xff20000000000000, #PEB -> important
        0x3b67,             #LastErrorValue
        0,                  #CountOfOwnedCriticalSections
        0,                  #CsrClientThread
        0xd30,              #Win32ThreadInfo
        (0,),               #User32Reserved
        (0,),               #UserReserved
        0,                  #WOW32Reserved
        0x412,              #CurrentLocale
        0,                  #FpSoftwareStatusRegister
        (0,),               #ReservedForDebuggerInstrumentation
        (0,),               #SystemReserved1
        0,                  #PlaceholderCompatibilityMode
        0,                  #PlaceholderHydrationAlwaysExplicit
        b'',                #PlaceholderReserved
        0,                  #ProxiedProcessId
        #_ActivationStack
        0,                  #ActiveFrame
        TEB_BASE+0x298,     #FrameListCache_Flink
        TEB_BASE+0x298,     #FrameListCache_Blink
        0x2,                #Flags
        0x1,                #NextCookieSequenceNumber
        0x2147dee,          #StackId
        #-----------------
        (0,),               #
        0,                  #
        (0,),               #
        TEB_BASE+0x290,     #ActivationContextStackPointer
        0,                  #InstrumentationCallbackSp
        0,                  #InstrumentationCallbackPreviousPc
        0,                  #InstrumentationCallbackPreviousSp
        0xfffe,             #TxFsContext
        0,                  #InstrumentationCallbackDisabled
        0,                  #UnalignedLoadStoreExceptions
        (0,),               #Padding1
        #_GDI_TEB_BATCH
        0x0,                
        0x0,           
        0x160000,           #0TEB+0x2F8 값비교
        (0,),
        #----------------
        0xdeadbeef,         #RealClientId_UniqueProcess
        0xdeadbeef,         #RealClientId_UniqueThread
        0,
        0,                  #GdiClientPID
        0,                  #GdiClientTID
        0,
        (0,),               #Win32ClientInfo[62]
        (0,),               #glDispatchTable[233]
        (0,),               #glReserved1
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        (0,),
        #_UNICODE_STRING
        0x0,
        0x20a,
        TEB_BASE+0x1268,
        #--------------
        u'ntdll.dll',
        (0,),
        0,
        (0,),               #TLS Slot
        0,                  #TlsLinks_Flink
        0,                  #TlsLinks_Blink
        0,                  #Vdm
        0,                  #ReservedForNtRpc
        (0,),
        0,
        (0,),
        (0,),               #Instrumentation
        #GUID
        0,                  
        0,
        0,
        (0,),
        #------------
        0,
        0,
        0,
        0,
        0,
        #_PROCESSOR_NUMBER
        0,
        0x2,
        0x2,
        #--------------
        0x2020000,
        0,
        0,
        0x2,
        0x2,
        0,
        (0,),
        0,
        0,
        0,
        (0,),
        0,                  #   +0x1768
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,                   #HeapData
        (0,),
        0,                   #CurrentTransactionHandle
        0,
        0,
        0,
        0,
        0,
        0,
        0,                  #CrossTebFlags
        # "SameTebFlags" #+0x17ee 
        0,
        0,
        0,
        0,
        0,
        1,
        0,
        0,
        0,
        0,
        1,
        0,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        #EffectiveContainerId
        0,
        0,
        0,
        (0,),
        #--------------------
        0,
        0,
        (0,),
        0
    )
    teb.ActivationContextStackPointer = 0x400000
    return teb
   
