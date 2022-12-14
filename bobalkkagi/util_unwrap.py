from ctypes import *
from capstone import *
from unicorn import *
from unicorn.x86_const import *
from dataclasses import dataclass

from .globalValue import DLL_SETTING, GLOBAL_VAR
from .util import saveDumpfile, align


import copy
import sys
import string
import struct
import math

origin_data = None

dll_dic ={}
api_dic = {}
api_count = {}
call_addrfunc = {}

dll_list=[]
call_rip = []

address_size = 0
hookint = 0
@dataclass
class _SECTION_MEMBER:
    virtualsize:int = None
    virtualaddress:int = None
    rawsize:int = None
    rawaddress:int = None

class _IMAGE_IMPORT_DESCRIPTOR(Structure):
    _fields_ = [
        ("OriginalFirstThunk", c_uint32),
        ("TimeDateStamp", c_uint32),
        ("ForwarderChain", c_uint32),
        ("Name", c_uint32),
        ("FirstThunk", c_uint32)
    ]

def readByte(offset):
    global origin_data
    return struct.unpack("<B", origin_data[offset:offset+1])[0]

def readBytes(offset,n):
    global origin_data
    return list(struct.unpack("<"+"B"*n, origin_data[offset:offset+n]))

def readWord(offset):
    global origin_data
    return struct.unpack("<H", origin_data[offset:offset+2])[0]

def readDword(offset):
    global origin_data
    return struct.unpack("<L", origin_data[offset:offset+4])[0]

def readDwords(offset,n):
    global origin_data
    return struct.unpack("<"+"L"*n, origin_data[offset:offset+4*n])

def readLword(offset):
    global origin_data
    return struct.unpack("<Q", origin_data[offset:offset+8])[0]

def readLwords(offset,n):
    global origin_data
    return struct.unpack("<"+"Q"*n, origin_data[offset:offset+8*n])

def readStringn(offset,n):
    global origin_data
    txt=""
    for x in range(n):
        char=struct.unpack("<B", origin_data[offset+x:offset+x+1])[0]
        if char in map(ord,string.printable) and char!=0:
            txt+=chr(char)
        else:
            break
    return txt

def writeByte(offset, data):
    global origin_data
    dat=struct.pack("<B",data)
    origin_data=origin_data[:offset]+dat+origin_data[offset+1:]

def writeWord(offset,data):
    global origin_data
    dat=struct.pack("<H",data)
    origin_data=origin_data[:offset]+dat+origin_data[offset+2:]

def writeDword(offset,data):
    global origin_data
    dat=struct.pack("<L",data)
    origin_data=origin_data[:offset]+dat+origin_data[offset+4:]
    
def writeLword(offset,data):
    global origin_data
    dat=struct.pack("<Q",data)
    origin_data=origin_data[:offset]+dat+origin_data[offset+8:]

def writeData(offset,data):
    global origin_data
    l=len(data)
    origin_data=origin_data[:offset]+data+origin_data[offset+l:] #data injection
    return l+1 # dll addr , api addr 

def newSection(lastSection_offset,sectionAlignment):
    rawSize = 0x0
    virtualSize = 0x0
    virtualsize = readDword(lastSection_offset+0x08)
    virtualaddress = readDword(lastSection_offset+0x0C)

    virtualAddress=virtualaddress+math.ceil(virtualsize/sectionAlignment)*sectionAlignment  # 새로운 섹션 VA 위치 계산(마지막 섹션의 최소 단위의 갯수 * 섹션 최소 단위 + 마지막 섹션 VA 위치)
    rawAddress=virtualaddress+math.ceil(virtualsize/sectionAlignment)*sectionAlignment # 새로운 섹션의 파일 offset 위치 계산 (unicorn에서 dump뜬 상태에서 파일로 저장하여 VA -> RA offset 동일해짐)
    #new_rawSize=math.ceil(address_size/sectionAlignment)*sectionAlignment
    #new_virtualSize=math.ceil(address_size/sectionAlignment)*sectionAlignment # 새로운 섹션의 size 계산
    characterstics=0xe0000060 # 섹션의 권한 설정

    rawSize += 0x8000
    virtualSize += 0x8000
    NewSN = "alkkagi"

    return virtualAddress, rawAddress, rawSize, virtualSize, characterstics, NewSN
    

def isCallSection(rip, Section_offset):
    section_num = readWord(readDword(0x3c)+0x06)
    try:
        for n in range(section_num):
            offset = Section_offset + (0x28 * n)
            rawsize = readDword(offset + 0x10)
            rawaddr = readDword(offset + 0x14)
            virtualaddr = readDword(offset + 0x0C)
            if(rawaddr <= rip and rip <= (rawaddr + rawsize)):
                return 1, virtualaddr - rawaddr
            else:
                return 0, 0
    except:
        return 0, 0

def isThemidaSection(rip):
    offset = readDword(rip+0x2)
    try:
        calladdr=readLword(rip + offset + 0x6)
        if(GLOBAL_VAR.themida[1] <= calladdr and calladdr < (GLOBAL_VAR.themida[1]+GLOBAL_VAR.themida[2])):
            return True
        else:
            return False
    except:
        return False

def disas(code, address):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    assem = md.disasm(code, address)
    return assem

def hook_mem_write_unmapped(uc, access, address, size, value, user_data):
    print("unmapped")
    print(hex(access), hex(address), hex(size), hex(value))
    code = uc.mem_read(address, size)
    asm=disas(bytes(code),address)
    print(code)
    print(asm)
    
    for a in asm:
        print("  0x%x: " % a.address +"\t%s" % a.mnemonic +"\t%s\n" % a.op_str)

def hooking_code(uc, address, size, user_data):
    print("address : ", hex(address))
    print("size : ", hex(size))
    code = uc.mem_read(address, size)
    asm=disas(bytes(code),address)
    for a in asm:
        print("  0x%x: " % a.address +"\t%s" % a.mnemonic +"\t%s\n" % a.op_str)

def find_api(uc, access, address, size, value, user_data):
    global dll_list
    global address_size
    global call_addrfunc
    global hookint

    # #print("==================================")
    # print("address : ", hex(address))
    # #print("size : ", hex(size))

    rsp = uc.reg_read(UC_X86_REG_RSP)
    if (hex(struct.unpack('<Q',uc.mem_read(rsp-0x8,8))[0])):
        dll_list.append(DLL_SETTING.InverseDllFuncs[address])
        funcName=DLL_SETTING.InverseDllFuncs[address].split('.dll_')[1]
        call_addrfunc[hex(user_data)]=[funcName]
        address_size += 0x8

    uc.hook_del(hookint)
    #print("Find funcion : ", hex(struct.unpack('<Q',uc.mem_read(rsp-0x8,8))[0]))
    uc.emu_stop()


def emulate_rip(uc, rip):
    global hookint
        
    uc.reg_write(UC_X86_REG_RAX, 0x0)
    uc.reg_write(UC_X86_REG_RCX, 0x0)
    uc.reg_write(UC_X86_REG_RDX, 0x0)
    uc.reg_write(UC_X86_REG_RBX, 0x0)
    uc.reg_write(UC_X86_REG_R8, 0x0)
    uc.reg_write(UC_X86_REG_R9, 0x0)
    uc.reg_write(UC_X86_REG_R10, 0x0)
    uc.reg_write(UC_X86_REG_R11, 0x0)
    uc.reg_write(UC_X86_REG_R12, 0x0)
    uc.reg_write(UC_X86_REG_RSP, 0x14ff28)
    uc.reg_write(UC_X86_REG_RBP, 0x0) 


    #uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_write_unmapped)
    hookint =uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, find_api, rip)
    #uc.hook_add(UC_HOOK_CODE, hooking_code)

    try:
        uc.emu_start(0x140000000 + rip, 0x140000000 + rip+0x20000) # imagebase + rip (call 위치에서 시작)
    except UcError as e:
        uc.emu_stop()
        pass
    
def emulate_start(origin_data):
    global dll_dic
    global api_count

    global dll_list
    global call_rip
    
    func_addrsize = 0x0

    StackBase = 0x201000
    StackLimit = 0x100000
    
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(0x140000000, 0x1000000, UC_PROT_ALL)

    uc.mem_write(0x140000000, origin_data)

    for ip in call_rip:
        
        uc.mem_map(StackLimit, StackBase - StackLimit, UC_PROT_ALL)
        emulate_rip(uc, ip)
        uc.mem_unmap(StackLimit, StackBase - StackLimit)
        uc.emu_stop()

    dll_list=list(set(dll_list))

    for dll_info in dll_list:
        dllName = dll_info.split('_')[0]
        funcName = dll_info.split('.dll_')[1]
        if dllName in dll_dic.keys():
            dll_dic[dllName].append(funcName)
            api_count[dllName]+=1
        else :
            dll_dic[dllName]=[funcName]
            api_count[dllName]= 1


def dump_restart(dump, OEP:int):
    global origin_data
    
    global dll_dic
    global api_dic
    global api_count
    global call_addrfunc

    global dll_list
    global call_rip
    
    global address_size    

    origin_data = bytes(dump)

    mzsignature=readWord(0x00) # e_magic
    peoffset=readDword(0x3c)   # e_lfanew
    pesignature=readDword(peoffset+0x00) # PE signature
    is_pefile=mzsignature==0x5a4d and pesignature==0x4550 # PE check

    if not is_pefile:
        sys.exit(0)
    else:
        sections_num=readWord(peoffset+0x06) # File Hdr. sections count
        imagebase=readLword(peoffset+0x30)  # Optional Hdr. Image Base
        sectionAlignment=readDword(peoffset+0x38) # Optional Hdr. Section Alignment

        fileAlignment=readDword(peoffset+0x3c)    # Optional Hdr. File Alignment 
        optionalhdr_size=readWord(peoffset+0x14)    # File Hdr. Size of OptionalHeadr
        Section_offset=peoffset+0x18+optionalhdr_size # 처음 시작하는 섹션 Hdr. offset
        
        lastSection_offset=peoffset+0x18+optionalhdr_size+(sections_num-1)*0x28
        lastSection_name=readStringn(lastSection_offset,8)        

        lastSection = _SECTION_MEMBER()
        lastSection.virtualsize = readDword(lastSection_offset+0x08)
        lastSection.virtualaddress = readDword(lastSection_offset+0x0C)
        ''''''
        # unicorn dump파일 oep set
        dumpSepoffset = (peoffset + 0x28) 
        writeDword(dumpSepoffset, (OEP - imagebase))

        # unicorn 덤프파일 pe Virtual -> RA
        dumpSection = _SECTION_MEMBER()
        for n in range(sections_num):
            dumpSection_offset = Section_offset + (n * 0x28)
            dumpSection.virtualsize = readDword(dumpSection_offset+0x08)
            dumpSection.virtualaddress = readDword(dumpSection_offset+0x0C)
            writeDword(dumpSection_offset + 0x14, dumpSection.virtualaddress)
            writeDword(dumpSection_offset + 0x10, dumpSection.virtualsize)
            if n < (sections_num-1):
                writeDword(dumpSection_offset + 0x8, (readDword(dumpSection_offset + 0x34) - readDword(dumpSection_offset+ 0xC)))

        '''''' # call emul
        rip = 0

        while (rip < (len(origin_data)-1)):
            if(hex(readWord(rip)) == '0x15ff'): # ff 15 little-endian
                call_check, section_size = isCallSection(rip, Section_offset)
                if call_check:
                    if isThemidaSection(rip):
                        call_rip.append(rip + section_size)
                    
            rip += 1
            
        emulate_start(origin_data)

        # 새로운 섹션 값 계산    
        new_virtualAddress, new_rawAddress, new_rawSize, new_virtualSize, new_characterstics ,NewSN = newSection(lastSection_offset,sectionAlignment)

        print("New Section Name:",NewSN)
        print("Virtual address:",hex(new_virtualAddress),"\nVirtual Size:",hex(new_virtualSize),"\nRaw Size:",hex(new_rawSize))
        print("Raw Address:",hex(new_rawAddress),"\nCharacterstics:",hex(new_characterstics))
        

        # 계산 값에 맞춰 Header 데이터 쓰기
        sectionheader=bytearray(NewSN.encode("utf-8")+b"\x00"*(8-len(NewSN)))+struct.pack("<LLLLLLLL",new_virtualSize,new_virtualAddress,new_rawSize,new_rawAddress,0,0,0,new_characterstics)
        newsize=new_virtualAddress+new_virtualSize
        sections_num += 1
        

        print("Section Header:"," ".join([str(hex(x))[2:] for x in sectionheader]),"\nSection Header Length:",len(sectionheader),"( "+str(hex(len(sectionheader)))+" )","\nNew file size:",newsize,"(",hex(newsize),")","\nNo of sections(updated):",sections_num)
        print("=====================================================")
        

        writeDword(peoffset+0x50,newsize) # Optional Hdr. Size of Image
        writeWord(peoffset+0x06,sections_num) # File Hdr. Sections Count
        writeData(lastSection_offset+0x28,sectionheader) # Header info insert
        writeDword(peoffset+0x58,0) #checksum = 0
        
        new_data=b"\x00"*(new_rawSize)
        origin_data=origin_data + new_data

        # Data 
        dll_addr={} # dll_name : addr
        api_addr={} # func_name : addr
        nameRVA = new_rawAddress + align(address_size, 0x100) # nameRVA offset
        
        for i in dll_dic:
            for j in dll_dic[i]:
                api_addr[j]=nameRVA
                nameRVA+=2
                nameRVA +=writeData(nameRVA, j.encode("utf-8"))
            dll_addr[i]=nameRVA    
            nameRVA +=writeData(nameRVA, i.encode("utf-8"))

        newSoffset = copy.deepcopy(new_rawAddress) # API OriginalFirstThunk
        newSimportaddress = align(nameRVA, 0x100) # IMAGE_IMPORT_DSCRIPTER 구조체
        newSimportaddressBase = newSimportaddress
        
        dll_OriginalFT = align(newSimportaddress + len(dll_dic)*20, 0x100) 
        func_addrsize = 0x0
        for i in dll_dic:
            Iid = _IMAGE_IMPORT_DESCRIPTOR()
            Iid.FirstThunk = newSoffset
            Iid.Name = dll_addr[i]
            Iid.OriginalFirstThunk = dll_OriginalFT
            for j in dll_dic[i]:
                #print(hex(DLL_SETTING.DllFuncs[i+"_"+j]))
                writeLword(newSoffset, DLL_SETTING.DllFuncs[i+"_"+j]) # API FirstThunk
                newSoffset+=0x8
                writeLword(dll_OriginalFT, api_addr[j])
                dll_OriginalFT+=0x8
                #FirstThunk저장 api_dic 딕셔너리에
                api_dic[j]=func_addrsize # func name : func addr offset
                func_addrsize += 0x8
            #newSoffset+=0x8
            dll_OriginalFT+=0x8
            origin_data=origin_data[:newSimportaddress]+bytes(Iid)+origin_data[newSimportaddress+0x14:]
            newSimportaddress += 0x14 #20byte
        writeDword(peoffset+0x90, newSimportaddressBase) #import address 주소 값 넣기

        # call operand 상대주소 변경
        for call_offset in call_addrfunc: # call_offset
            call_off = int(call_offset, 16)
            #call_virtualrip = imagebase + call_offset # Call offset + VA imagebase
            call_virtualrip = imagebase + call_off
            for compare_api in call_addrfunc[call_offset]: # func_name
                call_virtualvia = imagebase + new_virtualAddress + api_dic[compare_api]
            #writeDword(call_offset+0x2, call_virtualvia - call_virtualrip - 0x6)
            writeDword(call_off+0x2, call_virtualvia - call_virtualrip - 0x6)


        dumpFileName = GLOBAL_VAR.ProtectedFile.split('\\')[-1].split('.')[0] + '.dump'
        saveDumpfile(dumpFileName, origin_data)
        
        print("success")