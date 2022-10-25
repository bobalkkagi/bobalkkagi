import struct
import pefile
import os

def EndOfString(ByteData: bytes) -> str:
    byteString = ""
    for i in ByteData:
        if i == 0:
            break
        byteString += chr(i)
    
    return byteString

def GetDLLPath(dll:str)->str:
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

def DLL_Loader(uc, dllName, base, LOADED_DLL, DLL_FUNCTIONS) -> int: #return next dll load base 

    path = GetDLLPath(dllName)
    try :
        dll = pefile.PE(path, fast_load=True)
        LOADED_DLL[dllName] = base
        
        for section in dll.sections:
            code = section.get_data()
            uc.mem_write(base + section.VirtualAddress, code)
        
        dll.parse_data_directories()
        data = bytearray(dll.get_memory_mapped_image())
        
        Next_DLL_ADDRESS = ReturnDLLAddr(base + len(data))

        for entry in dll.DIRECTORY_ENTRY_EXPORT.symbols:
            try:
                DLL_FUNCTIONS[entry.name.decode('utf-8')] = base+entry.address
            except:
                pass

        print(f'[Load] {dllName}: {hex(base)}')
        return Next_DLL_ADDRESS

    except FileNotFoundError:
        print("{} isn't exist in {}".format(dllName, path))

def Insert_IAT(uc, pe, base, LOADED_DLL, DLL_FUNCTIONS, DLL_ADDRESS):
    
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

        if dll not in LOADED_DLL:
            DLL_ADDRESS = DLL_Loader(uc, dll, DLL_ADDRESS, LOADED_DLL, DLL_FUNCTIONS)
                
        max_len = len(pe.__data__) - file_offset
        dllnames_only=False
        import_data = [] # IAT에 저장되있는 함수들의 정보를 가져옴

        if not dllnames_only:
            try: #format에 맞게 파싱
                import_data = pe.parse_imports(
                    import_desc.OriginalFirstThunk,
                    import_desc.FirstThunk,
                    import_desc.ForwarderChain,
                    max_length=max_len,
                )
            except pefile.PEFormatError as e:
                pe.__warnings.append(
                "Error parsing the import directory. "
                f"Invalid Import data at RVA: 0x{0x2000:x} ({e.value})"
                )
        
        for funcs in import_data: # Unicorn으로 할당한 IAT공간에 함수들의 정보를 저장
            
            try:
                func_addr = DLL_FUNCTIONS[(funcs.name).decode('utf-8')]
            except:
                print(func_addr)
                input()
                continue

            uc.mem_write(base+funcs.address-imageBase,struct.pack('<Q', func_addr))
            
        rva += import_desc.sizeof()





