from unicorn import *
from unicorn.x86_const import *
import struct
import pefile
import os
from config import DLL_SETTING, GLOBALVAR, globar_var
from cache import cache_dll
from util import EndOfString

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

REFLECTOR = {
        "api-ms-win-core-sysinfo-l1-1-0.dll" : "kernelbase.dll",
        "api-ms-win-core-sysinfo-l1-2-0.dll" : "kernelbase.dll",
        "api-ms-win-core-sysinfo-l1-2-1.dll" : "kernelbase.dll",
        "api-ms-win-core-libraryloader-l1-2-0.dll" : "kernelbase.dll",
        "api-ms-win-core-libraryloader-l1-2-1.dll" : "kernelbase.dll",
        "api-ms-win-core-errorhandling-l1-1-0.dll" : "kernelbase.dll",
        "api-ms-win-core-libraryloader-l1-1-0.dll" : "kernelbase.dll",
        "api-ms-win-core-threadpool-legacy-l1-1-0.dll" : "kernelbase.dll",
        "api-ms-win-core-threadpool-private-l1-1-0.dll" : "kernelbase.dll",
        "api-ms-win-core-timezone-l1-1-0.dll" : "kernelbase.dll",
        "api-ms-win-crt-math-l1-1-0.dll" : "ucrtbase.dll",
        "api-ms-win-crt-time-l1-1-0.dll" : "ucrtbase.dll",
        "api-ms-win-crt-runtime-l1-1-0.dll" : "ucrtbase.dll",
        "api-ms-win-crt-heap-l1-1-0.dll" : "ucrtbase.dll",
        "api-ms-win-crt-heap-l1-1-0.dll" : "ucrtbase.dll",
        "api-ms-win-crt-utility-l1-1-0.dll": "ucrtbase.dll",
        "api-ms-win-crt-stdio-l1-1-0.dll" : "ucrtbase.dll",
        "api-ms-win-crt-locale-l1-1-0.dll" : "ucrtbase.dll",
        "api-ms-win-core-synch-l1-1-0.dll" : "ntdll.dll",
        "api-ms-win-core-heap-l1-1-0.dll" : "kernelbase.dll",
        "api-ms-win-core-processthreads-l1-1-0.dll" : "kernelbase.dll",
        "api-ms-win-core-processthreads-l1-1-1.dll" : "kernelbase.dll",
        "api-ms-win-core-processthreads-l1-1-2.dll" : "kernelbase.dll",
        "api-ms-win-core-xstate-l2-1-0.dll" : "kernelbase.dll",
        "api-ms-win-core-wow64-l1-1-0.dll" : "kernelbase.dll",
        "api-ms-win-core-realtime-l1-1-0.dll" : "kernelbase.dll",
        "api-ms-win-core-io-l1-1-0.dll" : "kernelbase.dll",
        "api-ms-win-core-io-l1-1-1.dll" : "kernelbase.dll",
        "api-ms-win-core-memory-l1-1-0.dll" : "kernelbase.dll",
        "api-ms-win-core-memory-l1-1-1.dll" : "kernelbase.dll",
        "api-ms-win-core-memory-l1-1-2.dll" : "kernelbase.dll",
        "api-ms-win-core-file-l1-1-0.dll" : "kernel32.dll",
        "api-ms-win-core-file-l1-2-0.dll" : "kernel32.dll",
        "api-ms-win-core-file-l1-2-1.dll" : "kernel32.dll",
        "api-ms-win-core-file-l2-1-0.dll" : "kernel32.dll",
        "api-ms-win-core-file-l2-1-1.dll" : "kernel32.dll",
        "api-ms-win-core-rtlsupport-l1-1-0.dll" : "kernel32.dll",
        "api-ms-win-core-console-l1-1-0.dll" : "kernel32.dll",
        "api-ms-win-eventing-provider-l1-1-0.dll" : "advapi32.dll",
        "api-ms-win-core-console-l1-1-0.dll" : "kernel32.dll",
        "api-ms-win-core-datetime-l1-1-0.dll" : "kernelbase.dll",
        "api-ms-win-core-datetime-l1-1-1.dll" : "kernelbase.dll",
        "api-ms-win-core-datetime-l1-1-2.dll" : "kernelbase.dll",
        "api-ms-win-core-debug-l1-1-0.dll" : "kernelbase.dll",
        "api-ms-win-core-debug-l1-1-1.dll" : "kernelbase.dll",
        "api-ms-win-core-fibers-l1-1-0.dll" : "kernel32.dll",
        "api-ms-win-core-handle-l1-1-0.dll" : "kernelbase.dll",
        "api-ms-win-core-localization-l1-2-0.dll" : "kernel32.dll",
        "api-ms-win-core-namedpipe-l1-1-0.dll" : "kernel32.dll",
        "api-ms-win-core-processenvironment-l1-1-0.dll" : "kernelbase.dll",
        "api-ms-win-core-processenvironment-l1-2-0.dll" : "kernelbase.dll",
        "api-ms-win-core-profile-l1-1-0.dll" : "kernel32.dll",
        "api-ms-win-core-string-l1-1-0.dll" : "kernel32.dll",
        "api-ms-win-core-synch-l1-2-0.dll" : "kernel32.dll",
        "api-ms-win-core-util-l1-1-0.dll" : "kernel32.dll",
        "api-ms-win-security-base-l1-1-0.dll" : "kernelbase.dll",
        "api-ms-win-security-base-l1-2-0.dll" : "kernelbase.dll",
        "api-ms-win-core-registry-l1-1-0.dll" : "kernelbase.dll",
        "api-ms-win-core-registry-l1-1-1.dll" : "kernelbase.dll",
        "api-ms-win-core-registry-l1-1-2.dll" : "kernelbase.dll",
        
    }
RTL = {
    "InitializeSListHead" : "RtlInitializeSListHead",
    "QueryUnbiasedInterruptTime" : "RtlQueryUnbiasedInterruptTime",
    "QueryPerformanceCounter" : "RtlQueryPerformanceCounter",
}


IMAGE_BASE_START = 0x140000000
IMAGE_BASE_END = 0x140000000
#DLL_BASE = 0x7FF000000000



def PE_Loader(uc, fileName, base, privilege=None, path=None) -> None: #
    global IMAGE_BASE_END
    #global DLL_BASE
    
    originBase = base
    dllFlag = False
    sectionInfo=[]
    if fileName in REFLECTOR:
        fileName = REFLECTOR[fileName]

    if ".dll" in fileName:
        dllFlag = True
        path = GetDLLPath(fileName, path)
    else :
        path = fileName


    try :
        pe = pefile.PE(path, fast_load=True)
        imageBase = pe.OPTIONAL_HEADER.ImageBase
        if dllFlag == True:
            if fileName.lower() not in DLL_SETTING.LOADED_DLL:
                DLL_SETTING.LOADED_DLL[fileName.lower()] = originBase
            else:
                return
            fileName = fileName.lower()
        alignHeaderSize = align(len(pe.header)) 
        uc.mem_map(base, alignHeaderSize, UC_PROT_READ)
        uc.mem_write(base, pe.header)
        base += alignHeaderSize
        sectionSize, sectionInfo = Section(uc, pe, originBase)
        base += sectionSize
        
        DataFix(uc, sectionInfo, originBase, imageBase, base-originBase) #imagebase 기준으로 저장된 정보를 load한 base주소 기준으로 변경, 예외처리가 필요할 수 있다.

        if dllFlag == True:
            GLOBALVAR['NEXT_DLL_BASE'] = base
        else :
            IMAGE_BASE_END = base
        pe.parse_data_directories()
        if dllFlag == True:
            for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if entry.name:
                    dllFunction = entry.name.decode('utf-8')
                try:
                    if dllFunction not in DLL_SETTING.DLL_FUNCTIONS:
                        if (fileName+"_"+dllFunction) in cache_dll:
                            DLL_SETTING.CACHE_DLL_FUNCTIONS[fileName+"_"+dllFunction] = originBase+entry.address
                        DLL_SETTING.DLL_FUNCTIONS[fileName+"_"+dllFunction] = originBase+entry.address
                    else:
                        print(f"ERROR! {dllFunction} is in DLL_FUNCTIONS")
                except:
                    pass
        
        Insert_IAT(uc, pe, originBase) #

        if fileName == "ntdll.dll":
            NtdllPatch(uc, originBase)

        print(f'[Load] {fileName}: {hex(originBase)}')
    except FileNotFoundError:
        pass


def Insert_IAT(uc, pe, base):
    #global DLL_BASE
    rva =pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress # DIRECTORY_ENTRY_IMPORT -> RVA
    imageBase = pe.OPTIONAL_HEADER.ImageBase 
    while True:
        if not rva:
            break
        image_import_descriptor_size = pefile.Structure(pe.__IMAGE_IMPORT_DESCRIPTOR_format__).sizeof() # size of import_discriptor
        data = pe.get_data(rva, image_import_descriptor_size) # rva 부터 image_import_descriptor_size만큼 데이터를 저장
        file_offset = pe.get_offset_from_rva(rva) # rva값으로부터 file_offset값 구하기
        
        import_desc = pe.__unpack_data__( # format에 맞게 data 파싱
                        pe.__IMAGE_IMPORT_DESCRIPTOR_format__, data, file_offset=file_offset)
        if not import_desc or import_desc.all_zeroes():
            break
        
        dll = pe.get_string_at_rva(import_desc.Name, pefile.MAX_DLL_LENGTH).decode('utf-8') # dll Name 가져오기

    
        if dll.lower() not in DLL_SETTING.LOADED_DLL:
            PE_Loader(uc, dll, GLOBALVAR['NEXT_DLL_BASE'], None, os.path.abspath("vm_dll"))
            #print(dll)     
        peDataLen = len(pe.__data__) - file_offset
        dllnames_only=False 
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
        origindll=dll
        for funcs in importData: # Unicorn으로 할당한 IAT공간에 함수들의 정보를 저장
            
            try:
                
                if dll in REFLECTOR:
                    dll = REFLECTOR[dll]
                funcName = (funcs.name).decode('utf-8')
                if funcName in RTL: # 특정함수는 rtl을 붙여 ntdll 내의 함수로 이동. 참고 https://overrun.tistory.com/27
                    funcName = RTL[funcName]
                    dll = "ntdll.dll"
                
                func_addr = DLL_SETTING.DLL_FUNCTIONS[dll.lower()+'_'+funcName]
                dll = origindll
            except:
                continue
            uc.mem_write(base+funcs.address-imageBase,struct.pack('<Q', func_addr))
            
        rva += import_desc.sizeof()



def align(value, pageSize=0x1000):
    m = value % pageSize
    f = 0
    if value % pageSize != 0:
        f = pageSize - m
    aligned_size = value + f
    return aligned_size  

def GetDLLPath(dll:str, path=None)->str:
    dllPath =""
    if path:
        root = path
    else:
        root = os.getcwd()
    for path, dirs, files in os.walk(root):
        for file in files:
            if file.lower() == dll.lower():
                dllPath = os.path.join(path, file)
                    
    return dllPath

def PrivChange(privilege):
    changeDic={0x2:0x10, 0x4:0x2, 0x6:0x20, 0xc:0x4, 0xe:0x40}
    return changeDic[privilege]

def Section(uc, pe, base):
    totalSize = 0
    info=[]
    for section in pe.sections:
        
        code = section.get_data()
        info.append([section.Name,base+section.VirtualAddress,align(section.Misc_VirtualSize),PRIVILEGE[section.Characteristics >>28]])
        uc.mem_map(base+section.VirtualAddress, align(section.Misc_VirtualSize) , PRIVILEGE[section.Characteristics >>28])
        uc.mem_write(base+section.VirtualAddress, code)
        totalSize += align(section.Misc_VirtualSize)
        globar_var.SECTIONINFO.append([base + section.VirtualAddress, section.Misc_VirtualSize, PrivChange(section.Characteristics >>28)])
    return totalSize, info

def DataFix(uc,sectionInfo,originbase,imagebase,offset):
    for section in sectionInfo:
        if section[3] <4:
            TPrivileage = section[3]
            uc.mem_protect(section[1],section[2],UC_PROT_READ | UC_PROT_WRITE)
            count = 0
            while count < section[2]:
                
                data = struct.unpack('<Q',uc.mem_read(section[1]+count,0x8))[0]
                if (data -imagebase) > 0 and (data-imagebase) < offset :
                    uc.mem_write(section[1]+count,struct.pack('<Q',data-imagebase+originbase))
                count += 0x8
            uc.mem_protect(section[1],section[2],TPrivileage)

def NtdllPatch(uc,base):
    uc.mem_write(base + 0x17A3F0,struct.pack('<Q',0x40000000006))
    uc.mem_write(base + 0x17A3F0+0x8,struct.pack('<Q',base + 0x1d510))
    uc.mem_write(base + 0x17A3F0+0x10,struct.pack('<Q',base + 0xA1215))
    uc.mem_write(base + 0x17A3F0+0x18,struct.pack('<Q',base ))
    uc.mem_write(base + 0x17A3F0+0x20,struct.pack('<Q',base + 0x16bdf8))
    uc.mem_write(base + 0x17A3F0+0x28,struct.pack('<Q',base ))
    uc.mem_write(base + 0x17A3F0+0x30,struct.pack('<Q',base + 0x170418)) 
    uc.mem_write(base + 0x17A3F0+0x38,struct.pack('<Q',base ))
    uc.mem_write(base + 0x17A3F0+0x40,struct.pack('<Q',base + 0x1728c0))
    uc.mem_write(base + 0x17A3F0+0x48,struct.pack('<Q',base ))
    uc.mem_write(base + 0x17A3F0+0x50,struct.pack('<Q',base + 0x16e828))
    uc.mem_write(base + 0x17A3F0+0x58,struct.pack('<Q',base ))
    uc.mem_write(base + 0x17A3F0+0x60,struct.pack('<Q',base + 0x16e81c))
    uc.mem_write(base + 0x17A3F0+0x68,struct.pack('<Q',base ))
    uc.mem_write(base + 0x17A3F0+0x70,struct.pack('<Q',base + 0x17277c))
    uc.mem_write(base + 0x17A370+0x8,struct.pack('<Q',0x2000000000000000))
   
def Remove_EXEC(sectionName:str, Characteristics, cnt:int):
    if len(sectionName) > 0 and sectionName != '.text':
        return Characteristics >> 28
    elif (Characteristics >> 28)&0x2:
        print(f"[Removed] No name {cnt}st section EXEC privilege!")
        return (Characteristics >> 28)^0x2 
    else:
        return Characteristics >> 28