import struct
import pefile
import os
from config import DLL_SETTING

def EndOfString(ByteData: bytes) -> str:
    byteString = ""
    for i in ByteData:
        if i == 0:
            break
        byteString += chr(i)
    
    return byteString

def GetDLLPath(dll:str, path=None)->str:
    if path:
        root = path
    else:
        root = "C:\\Windows\\System32\\"
    global dllPath
    for path, dirs, files in os.walk(root):
        if dll in files:
            dllPath = os.path.join(path, dll)
    return dllPath

#나중에 지울 수 있는 함수
def ReturnDLLAddr(addr): 
    loadedAddr = addr + 0x10000
    loadedAddr = (loadedAddr >> 16) << 16
    return loadedAddr #return loaded DLL address

def DLL_Loader(uc, dllName, base, userpath=None) -> int: #return next dll load base 

    lowerDllName = dllName.lower()
    path = GetDLLPath(lowerDllName, userpath) #path 부분 추가해서 사용

    try :
        dll = pefile.PE(path, fast_load=True)
        DLL_SETTING.LOADED_DLL[lowerDllName] = base
        uc.mem_write(base, dll.header)

        for section in dll.sections:
            code = section.get_data()
            uc.mem_write(base + section.VirtualAddress, code)
        
        dll.parse_data_directories()
        data = bytearray(dll.get_memory_mapped_image())
        
        Next_DLL_ADDRESS = ReturnDLLAddr(base + len(data))

        for entry in dll.DIRECTORY_ENTRY_EXPORT.symbols:

            if entry.name:
                dllFunction = entry.name.decode('utf-8')
            try:
                if dllFunction not in DLL_SETTING.DLL_FUNCTIONS:
                    DLL_SETTING.DLL_FUNCTIONS[lowerDllName+"_"+dllFunction] = base+entry.address
                else:
                    print(f"ERROR! {dllFunction} is in DLL_FUNCTIONS")
            except:
                pass

        print(f'[Load] {lowerDllName}: {hex(base)}')
        return Next_DLL_ADDRESS

    except FileNotFoundError:
        print("{} isn't exist in {}".format(dllName, path))

def Insert_IAT(uc, pe, base, DLL_ADDRESS):
    
    rva =pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress # DIRECTORY_ENTRY_IMPORT -> RVA
    imageBase = pe.OPTIONAL_HEADER.ImageBase 
    
    while True:
        image_import_descriptor_size = pefile.Structure(pe.__IMAGE_IMPORT_DESCRIPTOR_format__).sizeof() # size of import_discriptor
        data = pe.get_data(rva, image_import_descriptor_size) # rva 부터 image_import_descriptor_size만큼 데이터를 저장
        file_offset = pe.get_offset_from_rva(rva) # rva값으로부터 file_offset값 구하기
        
        import_desc = pe.__unpack_data__( # format에 맞게 data 파싱
                        pe.__IMAGE_IMPORT_DESCRIPTOR_format__, data, file_offset=file_offset)
        if not import_desc or import_desc.all_zeroes():
            break
        
        dll = pe.get_string_at_rva(import_desc.Name, pefile.MAX_DLL_LENGTH).decode('utf-8') # dll Name 가져오기

        if dll.lower() not in DLL_SETTING.LOADED_DLL:
            DLL_ADDRESS = DLL_Loader(uc, dll, DLL_ADDRESS)
                
        peDataLen = len(pe.__data__) - file_offset
        dllnames_only=False #어디에 쓸 줄 모르지만 일단 놔둠
        importData = [] # IAT에 저장되있는 함수들의 정보를 가져옴

        if not dllnames_only:
            try: #format에 맞게 파싱
                importData = pe.parse_imports(
                    import_desc.OriginalFirstThunk,
                    import_desc.FirstThunk,
                    import_desc.ForwarderChain,
                    max_length = peDataLen,
                )
            except pefile.PEFormatError as e:
                pe.__warnings.append(
                "Error parsing the import directory. "
                f"Invalid Import data at RVA: 0x{0x2000:x} ({e.value})"
                )
        
        for funcs in importData: # Unicorn으로 할당한 IAT공간에 함수들의 정보를 저장
            
            try:
                func_addr = DLL_SETTING.DLL_FUNCTIONS[dll+'_'+(funcs.name).decode('utf-8')]
            except:
                print(f"[DLL Setting Error] {funcs} not in DLL_FUNCTIONS")
                break

            uc.mem_write(base+funcs.address-imageBase,struct.pack('<Q', func_addr))
            
        rva += import_desc.sizeof()


