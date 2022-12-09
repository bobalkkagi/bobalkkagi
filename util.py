import pefile
import sys
import struct

def EndOfString(ByteData: bytes) -> str:
    byteString = ""
    for i in ByteData:
        if i == 0:
            break
        byteString += chr(i)
    
    return byteString

def calc_export_offset_of_dll(dllpath, function_name):
    """This function calculates the offset of exported function of a DLL. It is slow, so hardcoded values are used"""
    with open(dllpath, 'rb') as rf:
        dll = pefile.PE(data=rf.read())
    exports = dll.DIRECTORY_ENTRY_EXPORT.symbols
    for e in exports:
        if e.name == bytes(function_name, 'ascii'):
            return e.address
    return None

def getVirtualMemorySize(pe):
    sections = pe.sections
    min_offset = sys.maxsize
    total_size = 0
    for sec in sections:
        if sec.VirtualAddress < min_offset:
            min_offset = sec.VirtualAddress
        total_size += sec.Misc_VirtualSize
    total_size += min_offset
    return total_size

def align(value, pageSize=0x1000):
    m = value % pageSize
    f = 0
    if value % pageSize != 0:
        f = pageSize - m
    aligned_size = value + f
    return aligned_size 

def print_Dll_Map():
    from globalValue import PELoadDict
    sorted_dict = sorted(PELoadDict.items(), key = lambda item: item[1]) #return -> tuple 
    s = "="*40
    print(s+" DLL LOAD MAP "+s)
    for i, j in sorted_dict:
        print(f"{i:<50}: 0x{j:012x}")

    print("="*94)


def IsReadable(string):
    for ch in string:
        if 31 < ord(ch) < 127:
            pass
        else:
            return False
    
    return True

def PrintDict(dict: dict) -> None: #Print key, Hex(Value)
    for key in dict:
        print("key : {0}, value : {1}".format(key, hex(dict[key])))
    
def Devide8Bytes(bytedata):
    r = len(bytedata) % 8
    result = []
    if r != 0:
        bytedata += b'\x00' * (8-r)
    
    for i in range(len(bytedata)//8):
        result.append(struct.unpack('<Q', bytedata[i*8:(i+1)*8])[0])

    return result

def ViewMemory(addr, listdata):
    for i in range(len(listdata)//2):
        print(f'{addr+i*16:016x}: {listdata[i*2]:016x} {listdata[i*2+1]:016x}')