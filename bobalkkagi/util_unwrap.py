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

api_dic = {}
dll_dic ={}
calloffset_pattern={}
call_addrfunc = {}
mov_addrfunc = {}
jmp_addrfunc = {}

dll_api=[]
call_rip = []
mov_offset = []
jmp_offset = []

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
    imagebase = GLOBAL_VAR.ImageBaseStart
    writeLword(peoffset+0x30,imagebase)
    sectionAlignment=readDword(peoffset+0x38) # Optional Hdr. Section Alignment

    fileAlignment=readDword(peoffset+0x3c)    # Optional Hdr. File Alignment 
    optionalhdr_size=readWord(peoffset+0x14)    # File Hdr. Size of OptionalHeadr
    Section_offset=peoffset+0x18+optionalhdr_size # Hdr. offset
    
    lastSection_offset=peoffset+0x18+optionalhdr_size+(sections_num-1)*0x28

    if (func == "PEcompare"):
        return mzsignature, pesignature
    elif (func == "re"):
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


def modifyDump(OEP):
    # unicorn dump oep set
    peoffset, Section_offset, imagebase, sections_num = PEinfo("re", 0)

    Section_oepoffset = (peoffset + 0x28) 
    writeDword(Section_oepoffset, (OEP - imagebase))

    # unicorn dump file pe Virtual -> RA
    re = _SECTION_MEMBER()
    for n in range(sections_num):
        re_offset = Section_offset + (n * 0x28)
        re.virtualsize = readDword(re_offset+0x08)
        re.virtualaddress = readDword(re_offset+0x0C)
        writeDword(re_offset + 0x14, re.virtualaddress)
        writeDword(re_offset + 0x10, re.virtualsize)
        if n < (sections_num-1):
            writeDword(re_offset + 0x8, (readDword(re_offset + 0x34) - readDword(re_offset+ 0xC)))


def insertIAT(new_rawAddress):
    global origin_data
    # Data
    dll_addr={} # dll_name : addr
    api_addr={} # func_name : addr

    peoffset = PEinfo(0, "peoffset")
    nameRVA = new_rawAddress + align(address_size, 0x100) # nameRVA offset
    
    for dll in dll_dic:
        for api in dll_dic[dll]:
            api_addr[api]=nameRVA
            nameRVA+=2
            nameRVA +=writeData(nameRVA, api.encode("utf-8"))
        dll_addr[dll]=nameRVA    
        nameRVA +=writeData(nameRVA, dll.encode("utf-8"))   

    new_offset = copy.deepcopy(new_rawAddress) # API OriginalFirstThunk
    new_importaddress = align(nameRVA, 0x100) # IMAGE_IMPORT_DSCRIPTER struct
    importaddress_base = copy.deepcopy(new_importaddress)
    
    dll_OriginalFT = align(new_importaddress + len(dll_dic)*20, 0x100) 
    func_addrsize = 0x0
    for dll in dll_dic:
        Iid = _IMAGE_IMPORT_DESCRIPTOR()
        Iid.FirstThunk = new_offset
        Iid.Name = dll_addr[dll]
        Iid.OriginalFirstThunk = dll_OriginalFT
        for api in dll_dic[dll]:
            writeLword(new_offset, api_addr[api])
            new_offset+=0x8
            writeLword(dll_OriginalFT, api_addr[api])
            dll_OriginalFT+=0x8

            api_dic[api]=func_addrsize # func name : func addr offset
            func_addrsize += 0x8
        
        dll_OriginalFT+=0x8
        origin_data=origin_data[:new_importaddress]+bytes(Iid)+origin_data[new_importaddress+0x14:]
        new_importaddress += 0x14 #20byte
    writeDword(peoffset+0x90, importaddress_base) #import address write


def Injection_call(new_virtualAddress):
    callnext_jmp={}
    imagebase = PEinfo(0, "imagebase")
    
    for call_offset in call_addrfunc: # call_offset 
        #call_virtualrip = imagebase + call_offset # Call offset + VA imagebase
        
        call_virtualrip = imagebase + call_offset
        for compare_api in call_addrfunc[call_offset]: # func_name
            call_virtualvia = imagebase + new_virtualAddress + api_dic[compare_api]
      
        #ff15
        if (calloffset_pattern[call_offset] == 1):
            writeDword(call_offset+0x2, call_virtualvia - call_virtualrip - 0x6)
        #e8
        elif (calloffset_pattern[call_offset] == 2):
            operand = readDword(call_offset+0x1)
            operand_virtualaddr = call_virtualrip + operand + 0x5
            operand_offset = operand_virtualaddr - imagebase
            if(GLOBAL_VAR.ImageBaseStart <= operand_virtualaddr and operand_virtualaddr <= GLOBAL_VAR.ImageBaseEnd):
                callnext_jmp[operand_offset] = len(callnext_jmp)
                writeWord(operand_offset, 0x15ff)
                writeDword(operand_offset+0x2, call_virtualvia - operand_virtualaddr - 0x6)
                print("success : call change", hex(operand_offset), hex(call_offset))
            else:
                print("error : call change False", hex(operand_offset), hex(call_offset))
                for change in callnext_jmp:
                    if hex(readLword(change+(0x06+callnext_jmp[change]))) == "0xcccccccccccccccc":
                        callnext_jmp[change+(0x06+callnext_jmp[change])] = 0
                        writeWord(change+(0x6+callnext_jmp[change]), 0x15ff)
                        writeDword(change+((0x6+callnext_jmp[change])+0x2), call_virtualvia - (imagebase + (change+0x6+callnext_jmp[change])) - 0x6)
                        print("retry : call change", hex(change+0x6+callnext_jmp[change]), hex(call_offset))
                        break
                    else:
                        pass
        else:
            pass


def Injection_mov(new_virtualAddress):
    global mov_addrfunc

    imagebase = PEinfo(0, "imagebase")

    for mov_offset in mov_addrfunc: 
        mov_virtualrip = imagebase + mov_offset
        for compare_api in mov_addrfunc[mov_offset]: # func_name
            mov_virtualvia = imagebase + new_virtualAddress + api_dic[compare_api]
        
        writeDword(mov_offset+0x3, mov_virtualvia - mov_virtualrip - 0x7)
       

def Injection_jmp(new_virtualAddress):
    imagebase = PEinfo(0, "imagebase")
    
    for jmp_offset in jmp_addrfunc:        
        jmp_virtualrip = imagebase + jmp_offset
        if (jmp_addrfunc[jmp_offset] == None):
            pass
        else:
            for compare_api in jmp_addrfunc[jmp_offset]: # func_name
                # save api IAT addr find
                jmp_virtualvia = imagebase + new_virtualAddress + api_dic[compare_api]
            # jmp -> call change
            writeWord(jmp_offset, 0x15ff)
            writeDword(jmp_offset+0x2, jmp_virtualvia - jmp_virtualrip - 0x6)
            writeByte(jmp_offset+0x6, 0xcc)


def newSection():
    global origin_data
    
    peoffset, lastSection_offset, sectionAlignment, sections_num = PEinfo("newSection", 0)
    new_rawSize = 0x0
    new_virtualSize = 0x0
    new_virtualsize = readDword(lastSection_offset+0x08)
    new_virtualaddress = readDword(lastSection_offset+0x0C)

    new_virtualAddress=new_virtualaddress+math.ceil(new_virtualsize/sectionAlignment)*sectionAlignment
    new_rawAddress=new_virtualaddress+math.ceil(new_virtualsize/sectionAlignment)*sectionAlignment
    new_characterstics=0xe0000060

    new_rawSize += 0x8000
    new_virtualSize += 0x8000
    new_name = ".alkkagi"

    # new section data
    print("New Section Name:",new_name)
    print("Virtual address:",hex(new_virtualAddress),"\nVirtual Size:",hex(new_virtualSize),"\nRaw Size:",hex(new_rawSize))
    print("Raw Address:",hex(new_rawAddress),"\nCharacterstics:",hex(new_characterstics))
    
    # header info insert
    sectionheader=bytearray(new_name.encode("utf-8")+b"\x00"*(8-len(new_name)))+struct.pack("<LLLLLLLL",new_virtualSize,new_virtualAddress,new_rawSize,new_rawAddress,0,0,0,new_characterstics)
    newsize=new_virtualAddress+new_virtualSize
    sections_num += 1

    print(f"Section Header:", " ".join([str(hex(x))[2:] for x in sectionheader]))
    print(f"Section Header Length:",len(sectionheader),"( "+str(hex(len(sectionheader)))+" )")
    print(f"New file size: {newsize} ,{hex(newsize)}")
    print(f"Number of sections(updated): {sections_num}")
    
    print("=====================================================")

    writeDword(peoffset+0x50,newsize) # Optional Hdr. Size of Image
    writeWord(peoffset+0x06,sections_num) # File Hdr. Sections Count
    writeData(lastSection_offset+0x28,sectionheader) # Header info insert
    writeDword(peoffset+0x58,0) #checksum = 0
    
    new_data=b"\x00"*(new_rawSize)
    origin_data=origin_data + new_data

    return new_rawAddress

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
    global count
    
    if not (GLOBAL_VAR.themida[1] <= address and address < (GLOBAL_VAR.themida[1]+GLOBAL_VAR.themida[2])):
        count += 1
    elif count >= 1 and GLOBAL_VAR.themida[1] <= address and address < (GLOBAL_VAR.themida[1]+GLOBAL_VAR.themida[2]):
        count = 0
    if count >=4:
        count = 0
        uc.emu_stop()


def call_find_api(uc, access, address, size, value, user_data):
    global dll_api
    global hookint
    global hookint2
    global address_size

    #print("==================================")
    #print("offset : ", hex(user_data))
    #print("address : ", hex(address))
    #print("size : ", hex(size))
    
    rsp = uc.reg_read(UC_X86_REG_RSP)
    
    try:
        dll_api.append(DLL_SETTING.InverseDllFuncs[address])
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


def jmp_find_api(uc, access, address, size, value, user_data):
    global dll_api
    global hookint
    global hookint2
    global address_size

    #print("==================================")
    #print("offset : ", hex(user_data))
    #print("address : ", hex(address))
    #print("size : ", hex(size))
    
    rsp = uc.reg_read(UC_X86_REG_RSP)
   
    try:
        dll_api.append(DLL_SETTING.InverseDllFuncs[address])
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


def call_emulate_rip(uc, rip):
    global hookint
    global hookint2
    global count
    #print("==================================")#
    #print("call address :", hex(imagebase + rip))

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
    hookint = uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, call_find_api, rip)
    hookint2 = uc.hook_add(UC_HOOK_CODE, hooking_code)

    try:
        # imagebase + rip (call offset start)
        uc.emu_start(GLOBAL_VAR.ImageBaseStart + rip, GLOBAL_VAR.ImageBaseStart +rip+ 0x20000)
        uc.hook_del(hookint2)
        uc.hook_del(hookint)
    except UcError as e:
        uc.hook_del(hookint)
        uc.hook_del(hookint2)
        uc.emu_stop()
        pass

def jmp_emulate_rip(uc, rip):
    global hookint
    global hookint2
    #print("==================================")#
    #print("call address :", hex(imagebase + rip))
    
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
    hookint = uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, jmp_find_api, rip)
    hookint2 = uc.hook_add(UC_HOOK_CODE, hooking_code)

    try:
        # imagebase + rip (call rip start)
        uc.emu_start(GLOBAL_VAR.ImageBaseStart + rip, GLOBAL_VAR.ImageBaseStart +rip+ 0x20000)
        uc.hook_del(hookint2)
        uc.hook_del(hookint)
    except UcError as e:
        uc.hook_del(hookint)
        uc.hook_del(hookint2)
        uc.emu_stop()
        pass


def check_mov_Instruction(rip):
    global mov_addrfunc
    global dll_api

    try:
        offset = readDword(rip +3)
        address = readLword(offset + rip+ 7)
        try:
            #print(DLL_SETTING.InverseDllFuncs[address])
            dll_api.append(DLL_SETTING.InverseDllFuncs[address])
            funcName=DLL_SETTING.InverseDllFuncs[address].split('.dll_')[1]
            mov_addrfunc[rip] = [funcName]
        except:
            pass
    except :
        pass

def check_jmp_Instruction(rip):
    global jmp_addrfunc
    
    try:
        offset = readDword(rip + 3)
        address = readLword(offset + rip+ 7)
        if GLOBAL_VAR.themida[1] <= address and address < (GLOBAL_VAR.themida[1]+GLOBAL_VAR.themida[2]):
            jmp_addrfunc[rip] = None
    except :
        pass

    
def emulate_start():
    global origin_data

    global dll_api

    #uc.mem_map(0x140000000,0x850000, UC_PROT_ALL)
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(0x140000000, 0x1000000, UC_PROT_ALL)
    uc.reg_write(UC_X86_REG_GS_BASE, TebBase)
    StackBase = 0x201000
    StackLimit = 0x100000
    uc.mem_write(0x140000000, origin_data)
        

    for rip in calloffset_pattern:   
        uc.mem_map(StackLimit, StackBase - StackLimit, UC_PROT_ALL)
        call_emulate_rip(uc , rip)
        uc.mem_unmap(StackLimit, StackBase - StackLimit)

    for rip in jmp_offset:
        check_jmp_Instruction(rip)

    for rip in jmp_addrfunc:
        uc.mem_map(StackLimit, StackBase - StackLimit, UC_PROT_ALL)
        jmp_emulate_rip(uc , rip)
        uc.mem_unmap(StackLimit, StackBase - StackLimit)

    for rip in mov_offset:
        check_mov_Instruction(rip)

    dll_api=list(set(dll_api))

    for info in dll_api:
        dllName = info.split('_')[0]
        funcName = info.split('.dll_')[1]
        if dllName in dll_dic.keys():
            dll_dic[dllName].append(funcName)
            #api_count[dllName]+=1
        else :
            dll_dic[dllName]=[funcName]
            #api_count[dllName]= 1

def pattern_target():
    assem = Decode(GLOBAL_VAR.text[0], origin_data[GLOBAL_VAR.text[0]:GLOBAL_VAR.text[0]+GLOBAL_VAR.text[1]], Decode64Bits)

    for asm in assem:
        if asm[2].split(" ")[0] == "CALL":
            # instruction format
            if(asm[1] == 6):
                calloffset_pattern[asm[0]]=1
            elif(asm[1] == 5):
                calloffset_pattern[asm[0]]=2
            else:
                calloffset_pattern[asm[0]]=0

        if asm[2].split(" ")[0] == "MOV":
            mov_offset.append(asm[0])

        if asm[2].split(" ")[0] == "JMP":
            jmp_offset.append(asm[0])


def unwrapping(dump, OEP:int):
    global origin_data

    origin_data = bytes(dump)

    if not PEcompare():
        sys.exit(0)
    else:
        modifyDump(OEP)
        pattern_target()

        emulate_start()
        
        new_rawAddress = newSection()

        insertIAT(new_rawAddress)
        # unwrapping target operand addr change
        Injection_call(new_rawAddress)
        Injection_mov(new_rawAddress)
        Injection_jmp(new_rawAddress)

        dumpFileName = 'unwrap_'+GLOBAL_VAR.ProtectedFile.split('\\')[-1].split('.')[0] + '.dump'
        
        saveDumpfile(dumpFileName, origin_data)
        
        print("success")