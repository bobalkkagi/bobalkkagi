import sys
import struct
import os


def EndOfString(ByteData: bytes) -> str:
    byteString = ""
    for i in ByteData:
        if i == 0:
            break
        byteString += chr(i)
    
    return byteString

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

def printDllMap(Log:object, LoadedDLL:dict):
    sorted_dict = sorted(LoadedDLL.items(), key = lambda item: item[1])
    print("{0:=^100}".format("[ LOADED DLL ]"))
    for key, value in sorted_dict:
        Log.info(f"{key:<80}: {value:016x}")
    print("{0:=^100}".format("[ END ]"))
    


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

def saveDumpfile(file,data):
    print("[Create] Dumpfile!")
    if not os.path.isdir('dumpfiles'):
        os.mkdir('dumpfiles')
    if os.path.isfile(file):
        file = file + '_new'
    path = '\\'.join(['dumpfiles', file])
    f =open(path,'wb')
    f.write(data)
    f.close()

