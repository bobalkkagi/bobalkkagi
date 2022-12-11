from bobalkkagi.globalValue import GLOBAL_VAR, DLL_SETTING
from bobalkkagi.logger import regis
from bobalkkagi.util import Devide8Bytes, ViewMemory

import struct


def Debugger(uc: object, BobLog: object) -> bool:
    BobLog.debug("DEBUGING")

    while True:
        ud = input("UNICORN DEBUG > ").lower()

        if ud == 'q': #quit 

            print("FINISHED DEBUG")
            return False

        elif ud == 'n': #next
            return True

        elif ud == 'c': #continue
            return False

        elif ud == 's': #search
            while True:
                try:
                    addr = int(input("address : "), 16)
                    break
                except Exception as e:
                    print(f"[Error] {e}")
                    continue
            try:
                print(f"result: {DLL_SETTING.InverseDllFuncs[addr]}")
            except Exception as e:
                print(f"[Error] {e}")
        
        elif ud == 'sf': #search func
            while True:
                try:
                    addr = DLL_SETTING.DllFuncs[input("dll_function: ")]
                    break
                except Exception as e:
                    print(f"[Error] {e}")
                    continue
            
            print(f"result: {hex(addr)}")

        elif ud == 'w': #write memory
            while True:
                try:
                    addr = int(input("address: "), 16)
                    value = int(input("Value: "), 16)
                    break
                except Exception as e:
                    print(f"[Error] {e}")
                    continue
            try:
                print(f"before: {struct.unpack('<Q', uc.mem_read(addr, 0x8))[0]}")
                uc.mem_write(addr, struct.pack('<Q', value))
                print(f"Changed: {struct.unpack('<Q', uc.mem_read(addr, 0x8))[0]}")
            except Exception as e:
                print(f"[Error] {e}")

        elif ud == 'set': #set register
            while True:
                try:
                    reg = regis[input("regsister: ").upper()]
                    value = int(input("hex value: "), 16)
                    break
                except Exception as e:
                    print(f"[Error] {e}")
                    continue
            try:
                uc.reg_write(reg, value)
                BobLog.debug("Change register")
            except Exception as e:
                print(f"[Error] {e}")
        
        elif ud == 'view': #view memory
            while True:
                try:
                    addr= int(input("address(64bit size): "), 16)
                    value = int(input("size(ex. 0x1234): "), 16)
                    break
                except Exception as e:
                    print(f"[Error] {e}")
                    continue
            try:
                ViewMemory(addr, Devide8Bytes(uc.mem_read(addr, value)))
            except Exception as e:
                print(f"[Error] {e}")
        
        elif ud == 'bp':
            while True:
                try:
                    addr = int(input("address: "), 16)
                    break
                except Exception as e:
                    print(f"[Error] {e}")
                    continue
            GLOBAL_VAR.BreakPoint.append(addr)

        elif ud == 'bl':
            PrintBreakPoint(GLOBAL_VAR.BreakPoint)
        
        elif ud == 'd':
            GLOBAL_VAR.BreakPoint.pop(0)

        elif ud =='h':
            PrintDbgHelp()
        

def PrintDbgHelp()-> None:

    print("""
    ========= help ========
    q: quit
    n: next
    c: continue
    s: search dll function by address
    sf: search dll function by name
    w: write memory
    set: set register
    bp: breakpoint
    bl: breakpoint list
    view: view memory
    h: help
    ======================
    """)

def PrintBreakPoint(bpList: list) -> None:
    for idx, bp in enumerate(bpList):
        print(f"bp{idx}: {bp:016x}")