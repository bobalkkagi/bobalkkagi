import pefile
import sys

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

def merge(ranges):
    if not ranges:
        return []
    saved = list(ranges[0])
    for lower, upper in sorted([sorted(t) for t in ranges]):
        if lower <= saved[1] + 1:
            saved[1] = max(saved[1], upper)
        else:
            yield tuple(saved)
            saved[0] = lower
            saved[1] = upper
    yield tuple(saved)

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
