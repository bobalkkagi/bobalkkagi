from unicorn import UC_PROT_NONE, UC_PROT_EXEC, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_ALL

TebBase = 0xff10000000000000 # Same GS
PebBase = 0xff20000000000000
LdrBase = 0x000001B54C810000
ProcessHeapBase = 0x000001E9E3850000
MB = 2**20 #Mega Byte 0x100000
StackBase = 0x201000
StackLimit = 0x100000
KuserSharedDataBase = 0x000000007FFE0000
PshimDataBase = 0x600000
ActivationContextBase = 0x400000

PRIVILEGE = {
        0x0:UC_PROT_NONE,
        0x2:UC_PROT_EXEC, 
        0x4:UC_PROT_READ, 
        0x8:UC_PROT_WRITE, 
        0x6:UC_PROT_EXEC | UC_PROT_READ, 
        0xa:UC_PROT_EXEC | UC_PROT_WRITE, 
        0xc:UC_PROT_READ | UC_PROT_WRITE, 
        0xe:UC_PROT_ALL
    }

RTL = {
    "InitializeSListHead" : "RtlInitializeSListHead",
    "QueryUnbiasedInterruptTime" : "RtlQueryUnbiasedInterruptTime",
    "QueryPerformanceCounter" : "RtlQueryPerformanceCounter",
}