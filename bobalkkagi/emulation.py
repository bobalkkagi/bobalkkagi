from unicorn import *
from unicorn.x86_const import *
from datetime import datetime

from .loader import PE_Loader
from .logger import *
from .api_hook import *
from .globalValue import *
from .peb import Initpeb, InitProcessHeap
from .teb import InitTeb
from .kuserSharedData import InitKuserSharedData
from .hookFuncs import HookFuncs
from .constValue import *
from .debugger import Debugger
from .util import saveDumpfile

import logging
import struct
import pefile


# 64bit 맞게 수정


BobLog = logging.getLogger("Bobalkkagi")

def get_register(uc):
    register={
        "rax": uc.reg_read(UC_X86_REG_RAX),
        "rbx": uc.reg_read(UC_X86_REG_RBX),
        "rcx": uc.reg_read(UC_X86_REG_RCX),
        "rdx": uc.reg_read(UC_X86_REG_RDX),
        "rdi": uc.reg_read(UC_X86_REG_RDI),
        "rsi": uc.reg_read(UC_X86_REG_RSI),
        "rsp": uc.reg_read(UC_X86_REG_RSP),
        "rbp": uc.reg_read(UC_X86_REG_RBP),
        "rip": uc.reg_read(UC_X86_REG_RIP),
        "r8": uc.reg_read(UC_X86_REG_R8),
        "r9": uc.reg_read(UC_X86_REG_R9),
        "r10": uc.reg_read(UC_X86_REG_R10),
        "r11": uc.reg_read(UC_X86_REG_R11),
        "r12": uc.reg_read(UC_X86_REG_R12),
        "r13": uc.reg_read(UC_X86_REG_R13),
        "r14": uc.reg_read(UC_X86_REG_R14),
        "r15": uc.reg_read(UC_X86_REG_R15),
        "rflags": uc.reg_read(UC_X86_REG_EFLAGS),
    }

    return register


def hook_fetch(uc, access, address, size, value, user_data):
    
    print(hex(access),hex(address),hex(size),hex(value))
    rip=uc.reg_read(UC_X86_REG_RIP)
    print(hex(rip))

def hook_mem_read_unmapped(uc, access, address, size, value, user_data):
    print("unmapped")
    print(hex(access), hex(address), hex(size), hex(value))
    code = uc.mem_read(address, size)
    asm=disas(bytes(code),address)
    print(code)
    print(asm)
    
    for a in asm:
        print("  0x%x: " % a.address +"\t%s" % a.mnemonic +"\t%s\n" % a.op_str)
        

def hook_api(uc, address, size, user_data):
    rsp=uc.reg_read(UC_X86_REG_RSP)
    rip=uc.reg_read(UC_X86_REG_RIP)
    try:
        globals()["hook_"+GLOBAL_VAR.InverseHookFuncs[address-GLOBAL_VAR.HookRegion].split(".dll_")[1]](uc, BobLog, get_register(uc))
    except KeyError as e:
        BobLog.info("Not Found : "+str(e))
        pass
    

def hook_block(uc, address, size, user_data):
    exitFlag=0
    rsp=uc.reg_read(UC_X86_REG_RSP)
    rip=uc.reg_read(UC_X86_REG_RIP)

    try :
       if rip in DLL_SETTING.InverseDllFuncs:
            BobLog.info(f"This Function is {DLL_SETTING.InverseDllFuncs[rip]}, RIP : {hex(rip)}")

            if GLOBAL_VAR.DebugOption:
                GLOBAL_VAR.DebugFlag = True
                GLOBAL_VAR.DebugOption = False

            if rip in GLOBAL_VAR.BreakPoint:
                GLOBAL_VAR.DebugFlag = True

            exitFlag = globals()["hook_"+DLL_SETTING.InverseDllFuncs[rip].split(".dll_")[1]](uc, BobLog, get_register(uc))
            
            if exitFlag == 1:
                uc.emu_stop()
    except KeyError as e:
        #BobLog.info("Not Found : "+str(e))
        pass

    if GLOBAL_VAR.DebugFlag:
        GLOBAL_VAR.DebugFlag = Debugger(uc, BobLog)
    
    
def hook_code(uc, address, size, user_data):
    exitFlag=0
    rsp=uc.reg_read(UC_X86_REG_RSP)
    rip=uc.reg_read(UC_X86_REG_RIP)

    tmp = {hex(address):size}
    
    if get_len() >=get_size():
        p_queue()
    i_queue(tmp)
    
    try :
       if rip in DLL_SETTING.InverseDllFuncs:
            BobLog.info(f"This Function is {DLL_SETTING.InverseDllFuncs[rip]}, RIP : {hex(rip)}")
            
            if GLOBAL_VAR.DebugOption:
                GLOBAL_VAR.DebugFlag = True
                GLOBAL_VAR.DebugOption = False

            if rip in GLOBAL_VAR.BreakPoint:
                GLOBAL_VAR.DebugFlag = True

            exitFlag=globals()['hook_'+DLL_SETTING.InverseDllFuncs[rip].split('.dll_')[1]](uc, BobLog, get_register(uc))
        
            if exitFlag ==1:
                uc.emu_stop()
    except KeyError as e:
        #BobLog.info("Not Found : "+str(e))
        pass

    if GLOBAL_VAR.DebugFlag:
        GLOBAL_VAR.DebugFlag = Debugger(uc, BobLog)
    
    

def InsPatch(uc, address, size, user_data):
    rip=uc.reg_read(UC_X86_REG_RIP)
    rsp=uc.reg_read(UC_X86_REG_RSP)
    if size ==0xf1f1f1f1 :
        size = 0x3

    code = uc.mem_read(address, size)
    asm=disas(bytes(code),address)
    for a in asm:
        if a.mnemonic == "xrstor":
            uc.reg_write(UC_X86_REG_RIP,rip+0x3)
        if a.mnemonic == "iretq":
            nrip=struct.unpack('<Q',uc.mem_read(rsp,8))[0]
            nflags=struct.unpack('<Q',uc.mem_read(rsp+0x10,8))[0]
            nrsp=struct.unpack('<Q',uc.mem_read(rsp+0x18,8))[0]
            uc.reg_write(UC_X86_REG_RIP, nrip)
            uc.reg_write(UC_X86_REG_RSP, nrsp)
            uc.reg_write(UC_X86_REG_EFLAGS, nflags)
            uc.hook_del(GLOBAL_VAR.HookInt)

def InsertHookFlag(uc):
    for key in HookFuncs:
        address =DLL_SETTING.DllFuncs[key]
        offset = GLOBAL_VAR.HookRegion-address-5 + HookFuncs[key]
        byteOffset=struct.pack('<Q',offset)
        jmp = struct.pack('<B',0xE9)
        flagInstruction = (jmp+byteOffset)[:-1]
        uc.mem_write(address,flagInstruction)

def setUpStructure(uc: object) -> None: #Set up TEB, PEB, ProcessHeap, KuserSharedData Structure. If you Need More, you can add 
    global TebBase
    global PebBase
    global LdrBase
    global ProcessHeapBase
    global KuserSharedDataBase
    global PshimDataBase

    teb = InitTeb()
    peb = Initpeb()
    procHeap = InitProcessHeap()
    kuserSharedData = InitKuserSharedData()
    tebPayload = bytes(teb)
    pebPayload = bytes(peb)
    procHeapPayload = bytes(procHeap)
    kuserSharedDataPayload = bytes(kuserSharedData)

    uc.mem_map(TebBase, MB, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_map(PebBase, MB, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_map(LdrBase, MB, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_map(ProcessHeapBase, 10 * MB, UC_PROT_READ | UC_PROT_WRITE)
    # uc.mem_map(ActivationContextBase, 0x1000, UC_PROT_ALL) # Not Used
    uc.mem_map(KuserSharedDataBase, 0x1000, UC_PROT_READ)
    uc.mem_map(PshimDataBase, 0x2000, UC_PROT_READ | UC_PROT_WRITE)

    uc.mem_write(TebBase, tebPayload)
    uc.mem_write(PebBase, pebPayload)
    uc.mem_write(ProcessHeapBase, procHeapPayload)
    uc.mem_write(KuserSharedDataBase, kuserSharedDataPayload)
    uc.reg_write(UC_X86_REG_GS_BASE, TebBase)
    uc.reg_write(UC_X86_REG_CS, 0x400000)

def emulate(program: str,  verbose: bool, mode:str, oep: bool):
    start = datetime.now()
    print(f"\033[93m[{start}] Unpacking Start!\033[0m")

    pe = pefile.PE(program) # 실행할 프로그램 pe포멧으로 가져오기
    uc = Uc(UC_ARCH_X86, UC_MODE_64)

    
    EP = pe.OPTIONAL_HEADER.AddressOfEntryPoint #Entry Point
    uc.mem_map(StackLimit, StackBase - StackLimit, UC_PROT_ALL) #스택 공간

    PE_Loader(uc, program, GLOBAL_VAR.ImageBaseStart, oep)
    setUpStructure(uc)
    
    uc.mem_map(GLOBAL_VAR.HookRegion, 0x1000, UC_PROT_ALL)
    
    InvDllDict() # 함수 이름 : 주소 , -> 주소 : 이름

    #uc.reg_write(UC_X86_REG_RSP, STACK_BASE - pe.OPTIONAL_HEADER.SectionAlignment) #0x200000
    uc.reg_write(UC_X86_REG_RSP, 0x14ff28) #0x200000
    uc.reg_write(UC_X86_REG_RBP, 0x0) 
    
    InsertHookFlag(uc)
    InvHookFuncDict()
    
    print("\033[96m{0:=^100}\033[0m".format("[ Hook START ]"))
    
    #uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, hook_mem_read_unmapped)
    uc.hook_add(UC_HOOK_MEM_WRITE_PROT, hook_mem_read_unmapped)
    uc.hook_add(UC_HOOK_CODE, InsPatch, None,  DLL_SETTING.LoadedDll["ntdll.dll"], DLL_SETTING.LoadedDll["kernelbase.dll"])
    
    if mode == 'c':
        uc.hook_add(UC_HOOK_CODE, hook_code)
        verbose = True
    elif mode == 'b':
        GLOBAL_VAR.DebugOption = False # hook block mode can't debug
        verbose = True
        uc.hook_add(UC_HOOK_BLOCK, hook_block) 
    elif mode == 'f':
        uc.hook_add(UC_HOOK_BLOCK, hook_api, None, GLOBAL_VAR.HookRegion, GLOBAL_VAR.HookRegion + 0x1000)
    
    
    setup_logger(uc, BobLog, verbose)
    
    uc.reg_write(UC_X86_REG_RAX, GLOBAL_VAR.ImageBaseStart+EP)
    uc.reg_write(UC_X86_REG_RBX, 0x0)
    uc.reg_write(UC_X86_REG_RCX, PebBase)
    uc.reg_write(UC_X86_REG_RDX, GLOBAL_VAR.ImageBaseStart+EP)
    uc.reg_write(UC_X86_REG_R8, PebBase)
    uc.reg_write(UC_X86_REG_R9, GLOBAL_VAR.ImageBaseStart+EP)
    uc.reg_write(UC_X86_REG_EFLAGS, 0x244)
    
    try:
        uc.emu_start(GLOBAL_VAR.ImageBaseStart + EP, GLOBAL_VAR.ImageBaseEnd)
    except UcError as e:
        print("\033[96m{0:=^100}\033[0m".format("[ Hook End ]"))
        BobLog.error(f"{e}")
        OEP = uc.reg_read(UC_X86_REG_RIP)
        BobLog.info(f"Find OEP: {OEP:x}")


    if verbose:
        printDllMap(BobLog, DLL_SETTING.LoadedDll)
        

    end = datetime.now()
    print(f"\033[93m[{start}] Unpacking done...\033[0m")
    print(f"\033[94mRuntime: [{end-start}]\033[0m")
    
    dump= uc.mem_read(GLOBAL_VAR.ImageBaseStart, GLOBAL_VAR.ImageBaseEnd - GLOBAL_VAR.ImageBaseStart)
    oepOffset = OEP-GLOBAL_VAR.ImageBaseStart

    dumpFileName = program.split('\\')[-1].split('.')[0]+"_dump"
    #saveDumpfile(f'{dumpFileName}', dump)
    saveDumpfile("dumpfile", dump)
    return dump, oepOffset

