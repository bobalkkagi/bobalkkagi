from unicorn import *
from ctypes import *

class KSYSTEM_TIME(Structure):
    _fields_=[
        ("LowPart", c_uint32),
        ("High1Time", c_int32),
        ("High2Time", c_int32),
    ]

class XSTATE_FEATURE(Structure):
    _fields_=[
        ("Offset", c_uint32),
        ("Size", c_uint32),
    ]

class XSTATE_CONFIGURATION(Structure):
    _fields_=[
        ("EnabledFeatures", c_uint64),
        ("EnabledVolatileFeatures", c_int64),
        ("Size", c_uint32),
        ("ControlFlags", c_uint32),
        ("Features", XSTATE_FEATURE * 64),
        ("EnabledSupervisorFeatures", c_uint64),
        ("AlignedFeatures", c_uint64),
        ("AllFeatureSize", c_uint32),
        ("AllFeatures", c_uint32 * 64),
        ("EnabledUserVisibleSupervisorFeatures", c_uint64),
    ]

class LARGE_INTEGER(Structure):
    _fields_=[
        ("LowPart", c_uint32),
        ("HighPart", c_int32),
    ]


class KUSER_SHARED_DATA(Structure):
    _fields_=[
        ("TickCountLowDeprecated", c_uint32),               # 0x000
        ("TickCountMultiplier", c_uint32),                  # 0x004
        ("InterruptTime", KSYSTEM_TIME),                    # 0x008
        ("SystemTime", KSYSTEM_TIME),                       # 0x014
        ("TimeZoneBias", KSYSTEM_TIME),                     # 0x020
        ("ImageNumberLow", c_uint16),                       # 0x02c
        ("ImageNumberHigh", c_uint16),                      # 0x02e
        ("NtSystemRoot", c_uint16 * 260),                   # 0x030
        ("MaxStackTraceDepth", c_uint32),                   # 0x238
        ("CryptoExponent", c_uint32),                       # 0x23c
        ("TimeZoneId", c_uint32),                           # 0x240
        ("LargePageMinimum", c_uint32),                     # 0x244
        ("AitSamplingValue", c_uint32),                     # 0x248
        ("AppCompatFlag", c_uint32),                        # 0x24c
        ("RNGSeedVersion", c_uint64),                       # 0x250
        ("GlobalValidationRunlevel", c_uint32),             # 0x258
        ("TimeZoneBiasStamp", c_int32),                     # 0x25c
        ("NtBuildNumber", c_uint32),                        # 0x260
        ("NtProductType", c_uint32),                        # 0x264
        ("ProductTypeIsValid", c_char),                     # 0x268
        ("Reserved0", c_char),                              # 0x269
        ("NativeProcessorArchitecture", c_uint16),          # 0x26a
        ("NtMajorVersion", c_uint32),                       # 0x26c
        ("NtMinorVersion", c_uint32),                       # 0x270
        ("ProcessorFeatures", c_char*64),                   # 0x274
        ("Reserved1", c_uint32),                            # 0x2b4
        ("Reserved3", c_uint32),                            # 0x2b8
        ("TimeSlip", c_uint32),                             # 0x2bc
        ("AlternativeArchitecture", c_uint32),              # 0x2c0
        ("BootId", c_uint32),                               # 0x2c4
        ("SystemExpirationDate", LARGE_INTEGER),            # 0x2c8
        ("SuiteMask", c_uint32),                            # 0x2d0
        ("KdDebuggerEnabled", c_char),                      # 0x2d4
        ("MitigationPolicies", c_char),                     # 0x2d5
        ("CyclesPerYield", c_uint16),                       # 0x2d6
        ("ActiveConsoleId", c_uint32),                      # 0x2d8
        ("DismountCount", c_uint32),                        # 0x2dc
        ("ComPlusPackage", c_uint32),                       # 0x2e0
        ("LastSystemRITEventTickCount", c_uint32),          # 0x2e4
        ("NumberOfPhysicalPages", c_uint32),                # 0x2e8
        ("SafeBootMode", c_char),                           # 0x2ec
        ("VirtualizationFlags", c_char),                    # 0x2ed
        ("Reserved12", c_char * 2),                         # 0x26e
        ("SharedDataFlags", c_uint32),                      # 0x2f0
        ("DataFlagsPad", c_uint32),                         # 0x2f4
        ("TestRetInstruction", c_uint64),                   # 0x2f8
        ("QpcFrequency", c_int64),                          # 0x300
        ("SystemCall", c_uint32),                           # 0x308
        ("Reserved2", c_uint32),                            # 0x30c
        ("SystemCallPad", c_uint64 * 2),                    # 0x310
        ("TickCount", KSYSTEM_TIME),                        # 0x320
        ("TickCountPad", c_uint32),                         # 0x32c
        ("Cookie", c_uint32),                               # 0x330
        ("CookiePad", c_uint32),                            # 0x334
        ("ConsoleSessionForegroundProcessId", c_int64),     # 0x338
        ("TimeUpdateLock", c_uint64),                       # 0x340
        ("BaselineSystemTimeQpc", c_uint64),                # 0x348
        ("BaselineInterruptTimeQpc", c_uint64),             # 0x350
        ("QpcSystemTimeIncrement", c_uint64),               # 0x358
        ("QpcInterruptTimeIncrement", c_uint64),            # 0x360
        ("QpcSystemTimeIncrementShift", c_char),            # 0x368
        ("QpcInterruptTimeIncrementShift", c_char),         # 0x369
        ("UnparkedProcessorCount", c_uint16),               # 0x36a
        ("EnclaveFeatureMask", c_uint32 * 4),               # 0x36c
        ("TelemetryCoverageRound", c_uint32),               # 0x37c
        ("UserModeGlobalLogger", c_uint16 * 16),            # 0x380
        ("ImageFileExecutionOptions", c_uint32),            # 0x3a0
        ("LangGenerationCount", c_uint32),                  # 0x3a4
        ("Reserved4", c_uint64),                            # 0x3a8
        ("InterruptTimeBias", c_uint64),                    # 0x3b0
        ("QpcBias", c_uint64),                              # 0x3b8
        ("ActiveProcessorCount", c_uint32),                 # 0x3c0
        ("ActiveGroupCount", c_char),                       # 0x3c4
        ("Reserved9", c_char),                              # 0x3c5
        ("QpcBypassEnabled", c_char),                       # 0x3c6
        ("QpcShift", c_char),                               # 0x3c7
        ("TimeZoneBiasEffectiveStart", LARGE_INTEGER),      # 0x3c8
        ("TimeZoneBiasEffectiveEnd", LARGE_INTEGER),        # 0x3d0
        ("XState", XSTATE_CONFIGURATION),                   # 0x3d8
        ("FeatureConfigurationChangeStamp", KSYSTEM_TIME),  # 0x710
        ("Spare", c_uint32),                                # 0x71c
    ]


def InitKuserSharedData():
    kUserSharedData = KUSER_SHARED_DATA()
    kUserSharedData.KdDebuggerEnabled = 0x01
    kUserSharedData.MitigationPolicies = 0x0A
    kUserSharedData.XState.EnabledFeatures = 0xE7
    kUserSharedData.XState.ControlFlags = 0x3
    kUserSharedData.XState.AllFeatureSize = 0x980
    kUserSharedData.XState.AllFeatures[0] = 0xA0
    kUserSharedData.XState.AllFeatures[1] = 0x100
    kUserSharedData.XState.AllFeatures[2] = 0x100
    kUserSharedData.XState.AllFeatures[5] = 0x40
    kUserSharedData.XState.AllFeatures[6] = 0x200
    kUserSharedData.XState.AllFeatures[7] = 0x400
    kUserSharedData.XState.AllFeatures[9] = 0x8
    return kUserSharedData