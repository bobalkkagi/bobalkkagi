from ctypes import *
from capstone import *
from unicorn import *
from unicorn.x86_const import *
from distorm3 import Decode, Decode64Bits
from dataclasses import dataclass

from .globalValue import DLL_SETTING, GLOBAL_VAR
from .util import saveDumpfile, align
from .constValue import *

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
call_test={}
mov_offset = []
mov_addrfunc = {}
jmp_offset = []
jmp_addrfunc = {}
dll_list=[]
call_rip = []

address_size = 0
hookint = 0
hookint2 = 0
count = 0

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

def PEinfo(func, variable):
    mzsignature=readWord(0x00) # e_magic
    peoffset=readDword(0x3c)   # e_lfanew
    pesignature=readDword(peoffset+0x00) # PE signature

    sections_num=readWord(peoffset+0x06) # File Hdr. sections count
    #imagebase=readLword(peoffset+0x30)  # Optional Hdr. Image Base
    imagebase = GLOBAL_VAR.ImageBaseStart
    writeLword(peoffset+0x30,imagebase)
    sectionAlignment=readDword(peoffset+0x38) # Optional Hdr. Section Alignment

    fileAlignment=readDword(peoffset+0x3c)    # Optional Hdr. File Alignment 
    optionalhdr_size=readWord(peoffset+0x14)    # File Hdr. Size of OptionalHeadr
    Section_offset=peoffset+0x18+optionalhdr_size # 처음 시작하는 섹션 Hdr. offset
    
    lastSection_offset=peoffset+0x18+optionalhdr_size+(sections_num-1)*0x28

    if (func == "PEcompare"):
        return mzsignature, pesignature
    elif (func == "dumpSection"):
        return peoffset, Section_offset, imagebase, sections_num
    elif (func == "newSection"):
        return peoffset, lastSection_offset, sectionAlignment, sections_num
    elif (func == "FINDcall"):
        return imagebase, Section_offset, sections_num
    else:
        pass
    
    if (variable == "Section_offset"):
        return Section_offset
    elif (variable == "peoffset"):
        return peoffset
    elif (variable == "imagebase"):
        return imagebase
    else:
        pass

def PEcompare():
    mzsignature, pesignature = PEinfo("PEcompare", 0)
    is_pefile=mzsignature==0x5a4d and pesignature==0x4550 # PE check
    
    return is_pefile

def FINDcall(OEP):

    
        
    rip = GLOBAL_VAR.text[0] #section rawaddress
    while (GLOBAL_VAR.text[0] < (GLOBAL_VAR.text[1]-1)):
        if(hex(readWord(rip)) == '0x15ff'): # ff 15 little-endian
            call_check, section_size = isCallSection(rip)
            if call_check:
                if isThemidaSection(rip):
                    call_rip.append(rip + section_size)
        rip += 1
    
    return call_rip

def dumpSection(OEP):
    # unicorn dump파일 oep set
    peoffset, Section_offset, imagebase, sections_num = PEinfo("dumpSection", 0)

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

def insertIAT(new_rawAddress):
    global origin_data
    # Data
    dll_addr={} # dll_name : addr
    api_addr={} # func_name : addr
    nameRVA = new_rawAddress + align(address_size, 0x100) # nameRVA offset
    peoffset = PEinfo(0, "peoffset")

    for i in dll_dic:
        for j in dll_dic[i]:
            api_addr[j]=nameRVA
            nameRVA+=2
            nameRVA +=writeData(nameRVA, j.encode("utf-8"))
        dll_addr[i]=nameRVA    
        nameRVA +=writeData(nameRVA, i.encode("utf-8"))
    '''
    for i in api_addr:
        print("{0} : {1}".format(i,hex(api_addr[i])))
    for i in dll_addr:
        print("{0} : {1}".format(i,hex(dll_addr[i])))
    '''

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
            #writeLword(newSoffset, DLL_SETTING.DllFuncs[i+"_"+j]) # API FirstThunk
            writeLword(newSoffset, api_addr[j])
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

'''
def Injection_call(new_virtualAddress):
    # call operand 상대주소 변경
    imagebase = PEinfo(0, "imagebase")
    for call_offset in call_addrfunc: # call_offset
        call_off = int(call_offset, 16)
        #call_virtualrip = imagebase + call_offset # Call offset + VA imagebase
        call_virtualrip = imagebase + call_off
        for compare_api in call_addrfunc[call_offset]: # func_name
            call_virtualvia = imagebase + new_virtualAddress + api_dic[compare_api]
        #writeDword(call_offset+0x2, call_virtualvia - call_virtualrip - 0x6)
        ''''''
        
        ''''''
        writeDword(call_off+0x2, call_virtualvia - call_virtualrip - 0x6)
'''

def Injection_call(new_virtualAddress):
    call_test
    change_jmp={}
    global origin_data
    # call operand 상대주소 변경
    imagebase = PEinfo(0, "imagebase")
    
    for call_offset in call_addrfunc: # call_offset 
        #call_virtualrip = imagebase + call_offset # Call offset + VA imagebase
        
        call_virtualrip = imagebase + call_offset
        for compare_api in call_addrfunc[call_offset]: # func_name
            call_virtualvia = imagebase + new_virtualAddress + api_dic[compare_api]
        #writeDword(call_offset+0x2, call_virtualvia - call_virtualrip - 0x6)
      
        if (call_test[call_offset] == 1):
            writeDword(call_offset+0x2, call_virtualvia - call_virtualrip - 0x6)
        elif (call_test[call_offset] == 2):
            
            jmp = readDword(call_offset+0x1)
            jmp_virtualaddr = call_virtualrip + jmp + 0x5
            jmp_offset = jmp_virtualaddr - imagebase
            if(GLOBAL_VAR.ImageBaseStart <= jmp_virtualaddr and jmp_virtualaddr <= GLOBAL_VAR.ImageBaseEnd):
                change_jmp[jmp_offset] = len(change_jmp)
                writeWord(jmp_offset, 0x15ff)
                writeDword(jmp_offset+0x2, call_virtualvia - jmp_virtualaddr - 0x6)
                #print("success : call change", hex(jmp_offset), hex(call_offset))
            else:
                #print("error : call change False", hex(jmp_offset), hex(call_offset))
                for change in change_jmp:
                    if hex(readLword(change+(0x06+change_jmp[change]))) == "0xcccccccccccccccc":
                        change_jmp[change+(0x06+change_jmp[change])] = 0
                        writeWord(change+(0x6+change_jmp[change]), 0x15ff)
                        writeDword(change+((0x6+change_jmp[change])+0x2), call_virtualvia - (imagebase + (change+0x6+change_jmp[change])) - 0x6)
                        #print("retry : call change", hex(change+0x6+change_jmp[change]), hex(call_offset))
                        break
                    else:
                        pass
        else:
            pass

def Injection_mov(new_virtualAddress):
    global origin_data
    global mov_addrfunc
    # call operand 상대주소 변경
    imagebase = PEinfo(0, "imagebase")

    
    for mov_offset in mov_addrfunc: # call_offset 
        #call_virtualrip = imagebase + call_offset # Call offset + VA imagebase

        call_virtualrip = imagebase + mov_offset
        for compare_api in mov_addrfunc[mov_offset]: # func_name
            call_virtualvia = imagebase + new_virtualAddress + api_dic[compare_api]
        #writeDword(call_offset+0x2, call_virtualvia - call_virtualrip - 0x6)
        
        writeDword(mov_offset+0x3, call_virtualvia - call_virtualrip - 0x7)
       
def Injection_jmp(new_virtualAddress):
    global origin_data
    # call operand 상대주소 변경
    imagebase = PEinfo(0, "imagebase")
    
    for jmp_offset in jmp_addrfunc: # call_offset 
        #call_virtualrip = imagebase + call_offset # Call offset + VA imagebase
        
        call_virtualrip = imagebase + jmp_offset
        if (jmp_addrfunc[jmp_offset] == None):
            pass
        else:
            for compare_api in jmp_addrfunc[jmp_offset]: # func_name
                call_virtualvia = imagebase + new_virtualAddress + api_dic[compare_api]
            #writeDword(call_offset+0x2, call_virtualvia - call_virtualrip - 0x6)
            writeWord(jmp_offset, 0x15ff)
            writeDword(jmp_offset+0x2, call_virtualvia - call_virtualrip - 0x6)
            writeByte(jmp_offset+0x6, 0xcc)
        
def newSection():
    global origin_data
    peoffset, lastSection_offset, sectionAlignment, sections_num = PEinfo("newSection", 0)
    new_rawSize = 0x0
    new_virtualSize = 0x0
    new_virtualsize = readDword(lastSection_offset+0x08)
    new_virtualaddress = readDword(lastSection_offset+0x0C)

    new_virtualAddress=new_virtualaddress+math.ceil(new_virtualsize/sectionAlignment)*sectionAlignment  # 새로운 섹션 VA 위치 계산(마지막 섹션의 최소 단위의 갯수 * 섹션 최소 단위 + 마지막 섹션 VA 위치)
    new_rawAddress=new_virtualaddress+math.ceil(new_virtualsize/sectionAlignment)*sectionAlignment # 새로운 섹션의 파일 offset 위치 계산 (unicorn에서 dump뜬 상태에서 파일로 저장하여 VA -> RA offset 동일해짐)
    #new_rawSize=math.ceil(address_size/sectionAlignment)*sectionAlignment
    #new_virtualSize=math.ceil(address_size/sectionAlignment)*sectionAlignment # 새로운 섹션의 size 계산
    new_characterstics=0xe0000060 # 섹션의 권한 설정

    new_rawSize += 0x8000
    new_virtualSize += 0x8000
    NewSN = ".alkkagi"

    # 새로운 섹션 값 계산

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

    return new_rawAddress



def isCallSection(rip):
    Section_offset = PEinfo(0, "Section_offset")
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
    #print("unmapped")
    #print(hex(access), hex(address), hex(size), hex(value))
    code = uc.mem_read(address, size)
    asm=disas(bytes(code),address)
    #print(code)
    #print(asm)
    
    for a in asm:
        print("  0x%x: " % a.address +"\t%s" % a.mnemonic +"\t%s\n" % a.op_str)

def hooking_code(uc, address, size, user_data):
    global count
    
    
    #if jmp -> 
    if not (GLOBAL_VAR.themida[1] <= address and address < (GLOBAL_VAR.themida[1]+GLOBAL_VAR.themida[2])):
        count += 1
    elif count >= 1 and GLOBAL_VAR.themida[1] <= address and address < (GLOBAL_VAR.themida[1]+GLOBAL_VAR.themida[2]):
        count = 0
    if count >=4:
        count = 0
        uc.emu_stop()

def find_api(uc, access, address, size, value, user_data):
    call_addrfunc

    global dll_list
    global hookint
    global hookint2
    global address_size

    #print("==================================")
    #print("offset : ", hex(user_data))
    #print("address : ", hex(address))
    #print("size : ", hex(size))
    
    rsp = uc.reg_read(UC_X86_REG_RSP)
   
    
    try:
        dll_list.append(DLL_SETTING.InverseDllFuncs[address])
        funcName=DLL_SETTING.InverseDllFuncs[address].split('.dll_')[1]
        call_addrfunc[user_data]=[funcName]
        address_size += 0x8
    except :
        pass
        #print("error")
    #print("Find funcion : ", hex(struct.unpack('<Q',uc.mem_read(rsp-0x8,8))[0]))
    uc.hook_del(hookint2)
    uc.hook_del(hookint)
    uc.emu_stop()

def find_api2(uc, access, address, size, value, user_data):
    call_addrfunc

    global dll_list
    global hookint
    global hookint2
    global address_size

    #print("==================================")
    #print("offset : ", hex(user_data))
    #print("address : ", hex(address))
    #print("size : ", hex(size))
    
    rsp = uc.reg_read(UC_X86_REG_RSP)
   
    
    try:
        dll_list.append(DLL_SETTING.InverseDllFuncs[address])
        funcName=DLL_SETTING.InverseDllFuncs[address].split('.dll_')[1]
        jmp_addrfunc[user_data]=[funcName]
        address_size += 0x8
    except :
        pass
        #print("error")
    #print("Find funcion : ", hex(struct.unpack('<Q',uc.mem_read(rsp-0x8,8))[0]))
    uc.hook_del(hookint2)
    uc.hook_del(hookint)
    uc.emu_stop()

def emulate_rip(uc, rip):
    global hookint
    global hookint2
    global count
    #print("==================================")#
    #print("call address :", hex(imagebase + rip))
    
    count =0
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
    hookint = uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, find_api, rip)
    hookint2 = uc.hook_add(UC_HOOK_CODE, hooking_code)


    try:
        
        uc.emu_start(GLOBAL_VAR.ImageBaseStart + rip, GLOBAL_VAR.ImageBaseStart +rip+ 0x20000) # imagebase + rip (call 위치에서 시작)
        uc.hook_del(hookint2)
        uc.hook_del(hookint)
    except UcError as e:
        uc.hook_del(hookint)
        uc.hook_del(hookint2)
        uc.emu_stop()
        pass

def emulate_rip2(uc, rip):
    global hookint
    global hookint2
    global count
    #print("==================================")#
    #print("call address :", hex(imagebase + rip))
    
    count =0
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
    hookint = uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, find_api2, rip)
    hookint2 = uc.hook_add(UC_HOOK_CODE, hooking_code)


    try:
        
        uc.emu_start(GLOBAL_VAR.ImageBaseStart + rip, GLOBAL_VAR.ImageBaseStart +rip+ 0x20000) # imagebase + rip (call 위치에서 시작)
        uc.hook_del(hookint2)
        uc.hook_del(hookint)
    except UcError as e:
        uc.hook_del(hookint)
        uc.hook_del(hookint2)
        uc.emu_stop()
        pass

def check_mov_Instruction(rip):
    global mov_addrfunc
    global dll_list
    try:
        offset = readDword(rip +3)
        address = readLword(offset + rip+ 7)
        try:
            #print(DLL_SETTING.InverseDllFuncs[address])
            dll_list.append(DLL_SETTING.InverseDllFuncs[address])
            funcName=DLL_SETTING.InverseDllFuncs[address].split('.dll_')[1]
            mov_addrfunc[rip] = [funcName]
        except:
            pass
    except :
        pass

def check_jmp_Instruction(rip):
    global jmp_addrfunc
    global dll_list
    try:
        offset = readDword(rip + 3)
        address = readLword(offset + rip+ 7)
        if GLOBAL_VAR.themida[1] <= address and address < (GLOBAL_VAR.themida[1]+GLOBAL_VAR.themida[2]):
            jmp_addrfunc[rip] = None
    except :
        pass

'''
def emulate_rip(rip, origin_data):
    global hookint
    address = 0x140000000
    imagebase = 0x140000000
    StackBase = 0x201000
    StackLimit = 0x100000
    print("==================================")#
    print("call address :", hex(imagebase + rip))
    
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(0x140000000, 0x1000000, UC_PROT_ALL)
    uc.mem_map(StackLimit, StackBase - StackLimit, UC_PROT_ALL)

    uc.mem_write(0x140000000, origin_data)
        
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
    hookint = uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, find_api, rip)
    #uc.hook_add(UC_HOOK_CODE, hooking_code)

    try:
        uc.emu_start(imagebase + rip, address + 0x20000) # imagebase + rip (call 위치에서 시작)
    except UcError as e:
        uc.emu_stop()
        pass
'''
    
def emulate_start():
    global origin_data
    dll_dic
    api_count

    global dll_list
    global call_rip

    #uc.mem_map(0x140000000,0x850000, UC_PROT_ALL)

    for ip in call_rip:
        emulate_rip(ip, origin_data)

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
    
    dll_dic
    api_dic
    api_count
    call_addrfunc
    call_test

    global dll_list
    global call_rip
    global mov_offset
    global address_size    
    global jmp_offset
    global jmp_addrfunc
    origin_data = bytes(dump)

    if not PEcompare():
        sys.exit(0)
    else:
        dumpSection(OEP)
        #call_rip = FINDcall(OEP)

        
    
        l = Decode(GLOBAL_VAR.text[0], origin_data[GLOBAL_VAR.text[0]:GLOBAL_VAR.text[0]+GLOBAL_VAR.text[1]], Decode64Bits)
        for i in l:
            if i[2].split(" ")[0] == "CALL":
                if(i[1] == 6):
                    call_test[i[0]]=1
                elif(i[1] == 5):
                    call_test[i[0]]=2
                else:
                    call_test[i[0]]=0
            if i[2].split(" ")[0] == "MOV":
                mov_offset.append(i[0])
            if i[2].split(" ")[0] == "JMP":
                jmp_offset.append(i[0])

        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        uc.mem_map(0x140000000, 0x1000000, UC_PROT_ALL)
        uc.reg_write(UC_X86_REG_GS_BASE, TebBase)
        StackBase = 0x201000
        StackLimit = 0x100000
        uc.mem_write(0x140000000, origin_data)
        
        

        for rip in call_test:
           
            uc.mem_map(StackLimit, StackBase - StackLimit, UC_PROT_ALL)
            emulate_rip(uc , rip)
            uc.mem_unmap(StackLimit, StackBase - StackLimit)
    
        for rip in mov_offset:
            check_mov_Instruction(rip)

        for rip in jmp_offset:
            check_jmp_Instruction(rip)
        
        for rip in jmp_addrfunc:
            uc.mem_map(StackLimit, StackBase - StackLimit, UC_PROT_ALL)
            emulate_rip2(uc , rip)
            uc.mem_unmap(StackLimit, StackBase - StackLimit)
        
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
            
        #emulate_start()
        #print(call_addrfunc)
        new_rawAddress = newSection()
        insertIAT(new_rawAddress)
        # call operand 상대주소 변경
        Injection_call(new_rawAddress)
        Injection_mov(new_rawAddress)
        Injection_jmp(new_rawAddress)

        dumpFileName = GLOBAL_VAR.ProtectedFile.split('\\')[-1].split('.')[0] + '.dump'
        
        saveDumpfile(dumpFileName, origin_data)
        
        print("success")