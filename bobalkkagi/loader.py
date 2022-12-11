from unicorn import *
from unicorn.x86_const import *
from pathlib import Path

from bobalkkagi.globalValue import DLL_SETTING, GLOBAL_VAR
from bobalkkagi.constValue import PRIVILEGE, RTL
from bobalkkagi.reflector import REFLECTOR
from bobalkkagi.util import align

import struct
import pefile
import os


def PE_Loader(uc, fileName, base, oep: bool = False) -> None: #
  
    originBase = base
    dllFlag = False
    sectionInfo=[]


    if ".dll" in fileName:
        if fileName in REFLECTOR:
            fileName = REFLECTOR[fileName]
        dllFlag = True
        path = GetDLLPath(fileName)

    else :
        path = Path(fileName)


    try :
        pe = pefile.PE(path, fast_load=True)
        imageBase = pe.OPTIONAL_HEADER.ImageBase
        if dllFlag:
            if fileName.lower() not in DLL_SETTING.LoadedDll:
                DLL_SETTING.LoadedDll[fileName.lower()] = originBase
            else:
                return
            fileName = fileName.lower()
        alignHeaderSize = align(len(pe.header)) 
        uc.mem_map(base, alignHeaderSize, UC_PROT_READ)
        uc.mem_write(base, pe.header)
        GLOBAL_VAR.SectionInfo.append([base, 0x1000, 0x2]) # header
        base += alignHeaderSize
       
        sectionSize, sectionInfo = Section(uc, pe, originBase, oep)

        base += sectionSize
        
        DataFix(uc, sectionInfo, originBase, imageBase, base-originBase) #imagebase 기준으로 저장된 정보를 load한 base주소 기준으로 변경, 예외처리가 필요할 수 있다.

        pe.parse_data_directories()
        if dllFlag:
            GLOBAL_VAR.DllEnd = base
            for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if entry.name:
                    dllFunction = entry.name.decode('utf-8')
                try:
                    if dllFunction not in DLL_SETTING.DllFuncs:
                        DLL_SETTING.DllFuncs[fileName+"_"+dllFunction] = originBase+entry.address
                    else:
                        print(f"ERROR! {dllFunction} is in DllFuncs")
                except:
                    pass
        else:
            GLOBAL_VAR.ImageBaseEnd = base

        Insert_IAT(uc, pe, originBase) #

        if fileName == "ntdll.dll":
            NtdllPatch(uc, originBase)

        #print(f'[Load] {fileName:<80}: {originBase:016x}')
    except FileNotFoundError:
        pass


def Insert_IAT(uc, pe, base):
    
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

    
        if dll.lower() not in DLL_SETTING.LoadedDll:
            PE_Loader(uc, dll, GLOBAL_VAR.DllEnd)
    
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
        origindll = dll

        for funcs in importData: # Unicorn으로 할당한 IAT공간에 함수들의 정보를 저장
            
            try:
                
                if dll in REFLECTOR:
                    dll = REFLECTOR[dll]
                funcName = (funcs.name).decode('utf-8')
                if funcName in RTL: # 특정함수는 rtl을 붙여 ntdll 내의 함수로 이동. 참고 https://overrun.tistory.com/27
                    funcName = RTL[funcName]
                    dll = "ntdll.dll"
                
                func_addr = DLL_SETTING.DllFuncs[dll.lower()+'_'+funcName]
                dll = origindll
            except:
                continue
            uc.mem_write(base+funcs.address-imageBase,struct.pack('<Q', func_addr))
            
        rva += import_desc.sizeof()


def GetDLLPath(dll:str)->str:
    dllPath = ""
    for path, dirs, files in os.walk(GLOBAL_VAR.DirectoryPath):
        for file in files:
            if file.lower() == dll.lower():
                dllPath = os.path.join(path, file)
                    
    return dllPath

def PrivChange(privilege):
    changeDic={0x2:0x10, 0x4:0x2, 0x6:0x20, 0xc:0x4, 0xe:0x40}
    return changeDic[privilege]

def Section(uc, pe, base, oep):
    totalSize = 0
    info=[]

    for i, section in enumerate(pe.sections): 
        code = section.get_data()
        sectionName = str(section.Name, 'utf-8').replace(' ','').replace('\x00','')
        if oep:
            try:
                priv, sectionName = RemoveEXEC(sectionName, section.Characteristics)
                GLOBAL_VAR.text = [section.VirtualAddress, align(section.Misc_VirtualSize)]
            except:
                priv = RemoveEXEC(sectionName, section.Characteristics)
            
            info.append([section.Name,base+section.VirtualAddress, align(section.Misc_VirtualSize), PRIVILEGE[priv]])
            uc.mem_map(base+section.VirtualAddress, align(section.Misc_VirtualSize) , PRIVILEGE[priv])
            GLOBAL_VAR.SectionInfo.append([base + section.VirtualAddress, section.Misc_VirtualSize, PrivChange(priv)])
        else:
            info.append([section.Name,base+section.VirtualAddress,align(section.Misc_VirtualSize),PRIVILEGE[section.Characteristics >>28]])
            uc.mem_map(base+section.VirtualAddress, align(section.Misc_VirtualSize) , PRIVILEGE[section.Characteristics >>28])
            GLOBAL_VAR.SectionInfo.append([base + section.VirtualAddress, section.Misc_VirtualSize, PrivChange(section.Characteristics >>28)])

        uc.mem_write(base+section.VirtualAddress, code)
        totalSize += align(section.Misc_VirtualSize)
        
    return totalSize, info

def DataFix(uc, sectionInfo, originbase, imagebase, offset):
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
   
def RemoveEXEC(sectionName:str, Characteristics):
    if len(sectionName) > 0 and sectionName != '.text':
        return Characteristics >> 28
    elif (Characteristics >> 28)&0x2:
        #print(f"[Removed] No name {cnt} st section EXEC privilege!")
        return (Characteristics >> 28)^0x2, '.text'
    else:
        return Characteristics >> 28