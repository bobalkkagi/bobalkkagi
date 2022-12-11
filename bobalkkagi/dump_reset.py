from capstone import *
from unicorn import *
from unicorn.x86_const import *

from .globalValue import DLL_SETTING

import sys
import os 
import string
import struct
import math

list=[]
ripS = []
tdata = None
addr = []

def readWord(offset):
    global tdata
    return struct.unpack("<H",tdata[offset:offset+2])[0] # "<": 리틀 엔디안, ">": 빅 엔디안, "B": 1Byte, "H": 2Byte, "L": 4Byte, "Q": 8Byte

def readDword(offset):
    global tdata
    return struct.unpack("<L",tdata[offset:offset+4])[0]

def readDwords(offset,n):
    global tdata
    return struct.unpack("<"+"L"*n,tdata[offset:offset+4*n])

def readLword(offset):
    global tdata
    return struct.unpack("<Q",tdata[offset:offset+8])[0]

def readLwords(offset,n):
    global tdata
    return struct.unpack("<"+"Q"*n,tdata[offset:offset+8*n])

def readByte(offset):
    global tdata
    return struct.unpack("<B",tdata[offset:offset+1])[0]

def readbytes(offset,n):
    global tdata
    return list(struct.unpack("<"+"B"*n,tdata[offset:offset+n]))

def readStringn(offset,n):
    global tdata
    txt=""
    for x in range(n):
        char=struct.unpack("<B",tdata[offset+x:offset+x+1])[0]
        if char in map(ord,string.printable) and char!=0:
            txt+=chr(char)
        else:
            break
    return txt

def writeByte(offset, data):
    global tdata
    dat=struct.pack("<B",data)
    tdata=tdata[:offset]+dat+tdata[offset+1:]

def writeWord(offset,data):
    global tdata
    dat=struct.pack("<H",data)
    tdata=tdata[:offset]+dat+tdata[offset+2:]

def writeDword(offset,data):
    global tdata
    dat=struct.pack("<L",data)
    tdata=tdata[:offset]+dat+tdata[offset+4:]

def writeDwords(offset,data, n): # 이 함수는 안될 수 있음
    global tdata
    dat=struct.pack("<"+"L"*n, data)
    tdata=tdata[:offset]+dat+tdata[offset+4*n:]

def writeData(offset,data):
    global tdata
    l=len(data)
    tdata=tdata[:offset]+data+tdata[offset+l:] # 마지막 Section Header부분까지의 데이터 + 새로운 섹션의 Header 정보 + 새로운 섹션을 더한 Section Header의 마지막 부분 이후부터의 데이터

def writeLword(offset,data):
    global tdata
    dat=struct.pack("<Q",data)
    tdata=tdata[:offset]+dat+tdata[offset+8:]

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
    global list
    global addr
    #print("==================================")
    print("address : ", hex(address))
    print("size : ", hex(size))

    tmp = address
    with open('./bin/pay','ab') as payload:
            payload.write(str(hex(tmp)).encode('utf-8'))
            payload.close() 
    
    list.append(DLL_SETTING.InverseDllFuncs[address])
    addr.append(address.encode('utf-8'))
    #rsp = uc.reg_read(UC_X86_REG_RSP)
    #print("Find funcion : ", hex(struct.unpack('<Q',uc.mem_read(rsp-0x8,8))[0]))
    
def dstart(tdata):
    global list
    global ripS
    
    address = 0x140000000
    imagebase = 0x140000000
    #rip = [0x1038, 0x1057, 0x1093, 0x1246, 0x1590, 0x159e, 0x15aa, 0x15ba, 0x16a0, 0x16cd, 0x16e7, 0x1728, 0x177c, 0x179d, 0x17a8, 0x17de, 0x18ba, 0x18f6]


    for ip in ripS:
        print("==================================")#
        print("call address :", hex(imagebase + ip))
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        StackBase = 0x201000
        StackLimit = 0x100000

        uc.mem_map(0x140000000,0x850000, UC_PROT_ALL)
        uc.mem_map(StackLimit, StackBase - StackLimit, UC_PROT_ALL)

        uc.mem_write(0x140000000,tdata)
            
        uc.reg_write(UC_X86_REG_RAX, 0x0)
        uc.reg_write(UC_X86_REG_RCX, 0x0)
        uc.reg_write(UC_X86_REG_RDX, 0x0)
        uc.reg_write(UC_X86_REG_RBX, 0x0)
        uc.reg_write(UC_X86_REG_R9, 0x0)
        uc.reg_write(UC_X86_REG_RSP, 0x14ff28)
        uc.reg_write(UC_X86_REG_RBP, 0x0) 


        #uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_write_unmapped)
        uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, find_api)
        #uc.hook_add(UC_HOOK_CODE, hooking_code)
        uc.emu_stop()
        try:
            uc.emu_start(imagebase + ip, address + 0x2000) # imagebase + rip (call 위치에서 시작)
        except UcError as e:
            pass
    print(list)
    ''''''


def dump_restart(dumps, OEP:int):
    global ripS
    global tdata
    global addr
    
    with open("dumpfile","rb") as target:
        tdata=target.read()

    mzsignature=readWord(0x00) # DOS signature (e_magic)
    peoffset=readDword(0x3c)   # 파일 시작부분부터 pe헤더까지 offset (NT Header Offset) (e_lfanew)
    pesignature=readDword(peoffset+0x00) # PE signature
    is_pefle=mzsignature==0x5a4d and pesignature==0x4550 # PE파일 확인 (1==PE파일, 0==PE파일 아님)

    if not is_pefle:
        sys.exit(0)
    else:
        noSections=readWord(peoffset+0x06) # File Hdr. sections count
        imagebase=readLword(peoffset+0x30)  # Optional Hdr. Image Base
        sectionAlignment=readDword(peoffset+0x38) # Optional Hdr. Section Alignment (메모리에서 섹션의 최소 단위 (시작 주소는 해당 값의 배수))
        
        fileAlignment=readDword(peoffset+0x3c)    # Optional Hdr. File Alignment (파일에서 섹션의 최소 단위 (파일 섹션의 시작 주소는 해당 값의 배수))
        szoptionalhdr=readWord(peoffset+0x14)    # File Hdr. Size of OptionalHeadr (Optional Header 크기)

        print("=====================================================")
        print("NT Header(PE Header) Offset:",hex(peoffset),"\nImage Base:",hex(imagebase),"\nSection Alignment:",sectionAlignment,"(",hex(sectionAlignment),")")
        print("File Alignment:",fileAlignment,"(",hex(fileAlignment),")","\nNumber of sections:",noSections)
        
        lastSoffset=peoffset+0x18+szoptionalhdr+(noSections-1)*0x28  # (peoffset+0x18)(file Hdr 크기) + szoptionalhdr(optional hdr 크기) + 마지막 섹션 크기 제외한 섹션크기
        lastSname=readStringn(lastSoffset,8)
        
        print("last section offset:",hex(lastSoffset),"\nlast Section name:",lastSname)
        print("=====================================================")

        lastSvirtualSize,lastSvirtualAddress,lastSrawSize,lastSrawAddress=readDwords(lastSoffset+0x08,4) # 마지막 섹션의 멤버 값


        ''''''
        # unicorn dump파일 oep set
        dumpSepoffset = (peoffset + 0x28)    
        dumpSoep = imagebase + OEP#0x140001300  # emulation.py에 Find OEP에서 가져올것
        writeDword(dumpSepoffset, (dumpSoep - imagebase))

        # unicorn 덤프파일 pe Virtual -> RA
        for n in range(noSections):
            dumpSoffset = peoffset+0x18 + szoptionalhdr + (n * 0x28)
            dumpSvirtualSize, dumpSvirtualAddress, dumpSrawSize, dumpSrawAddress = readDwords(dumpSoffset+0x08,4)
            writeDword(dumpSoffset + 0x14, dumpSvirtualAddress)
            writeDword(dumpSoffset + 0x10, dumpSvirtualSize)
            if n < (noSections-1):
                writeDword(dumpSoffset + 0x8, (readDword(dumpSoffset + 0x34) - readDword(dumpSoffset+ 0xC)))

            ''' # unicorn으로 덤프뜬 파일 섹션 VA주소에 저장되있는 데이터 RA로 옮기려 시도
            # RA 깔끔하게 하려면 여기서 데이터를 한번에 가져와서 RA에 한번에 저장하는 방식으로
            tmp = dumpSvirtualAddress
            while (dumpSvirtualAddress <= tmp and tmp <= (dumpSvirtualAddress + dumpSvirtualSize)):
                #if ((n+1) == noSections):
                #    writeEnd()
                writeLword(dumpSrawAddress, readLword(tmp))
                writeLword(tmp, 0)
                tmp += 0x8
            '''


        ''''''



        '''''' # call emul
        rip = 0

        while (rip < (len(tdata)-1)):
            if(hex(readWord(rip)) == '0x15ff'): # ff 15 little-endian
                
                Soffset=peoffset+0x18+szoptionalhdr # 처음 시작하는 섹션 Hdr. offset
                n = 0 # 섹션 위치 제어 변수

                if  (n < noSections):
                    ripSoffset = Soffset + (0x28 * n)
                    ripSvirtualSize,ripSvirtualAddress,ripSrawSize,ripSrawAddress = readDwords(ripSoffset+0x08,4)
                    n += 1
                    if (ripSrawAddress <= rip and rip <= (ripSrawAddress + ripSrawSize)): # 현재 ff 15가 위치한 offset의 섹션 확인
                        ripS.append(rip - ripSrawAddress + ripSvirtualAddress) # 섹션의 VA offset값
                        
                        #print(hex(ripS))#, ",", "Absolute", hex(imagebase+ripS))
                        #tmp = readWord(rip)
                        # print(hex(tmp)) # call맞나 확인 (0x15ff출력됨(ff 15))

                # 향후 e8 call사용하려면 jmp인지 확인해볼것 if (rip +1) == jmp * 여기 rip는 다른 위에랑 다른 rip변수
                # call부터 jmp or jmp 일때, 레지스터 값 pay.txt에 저장

            rip += 1 # 해당 위치가 ff 15인지 확인하는 제어변수

        dstart(tdata)
        ''''''


        print("=====================================================")
        
        payload_size=os.stat("./bin/pay.txt").st_size  # 이거 전에 call 에뮬 돌려서 원본 API 주소 값 해당 위치에서 저장시킬것

        # 새로운 섹션 값 계산
        print("new section data size : "+str(payload_size/1024)+" KB")
    
        payload_virtualAddress=lastSvirtualAddress+math.ceil(lastSvirtualSize/sectionAlignment)*sectionAlignment  # 새로운 섹션 VA 위치 계산(마지막 섹션의 최소 단위의 갯수 * 섹션 최소 단위 + 마지막 섹션 VA 위치)
        #payload_rawAddress=lastSrawAddress+math.ceil(lastSrawSize/fileAlignment)*fileAlignment # 새로운 섹션의 파일 offset 위치 계산
        payload_rawAddress=lastSvirtualAddress+math.ceil(lastSvirtualSize/sectionAlignment)*sectionAlignment # 새로운 섹션의 파일 offset 위치 계산 (unicorn에서 dump뜬 상태에서 파일로 저장하여 VA -> RA offset 동일해짐)
        payload_rawSize=math.ceil(payload_size/fileAlignment)*fileAlignment # 새로운 섹션의 파일 offset size 계산(새로운 섹션에 삽입할 바이너리 크기의 최소 크기의 갯수 * 최소 파일의 크기)
        payload_virtualSize=math.ceil(payload_size/sectionAlignment)*sectionAlignment # 새로운 섹션의 size 계산
        payload_characterstics=0xe0000060 # 섹션의 권한 설정

        NewSN = ".IT"
        print("New Section Name:",NewSN)
        print("Virtual address:",hex(payload_virtualAddress),"\nVirtual Size:",hex(payload_virtualSize),"\nRaw Size:",hex(payload_rawSize))
        print("Raw Address:",hex(payload_rawAddress),"\nCharacterstics:",hex(payload_characterstics))
        
        # 계산 값에 맞춰 Header 데이터 쓰기
        sectionheader=bytearray(NewSN.encode("utf-8")+b"\x00"*(8-len(NewSN)))+struct.pack("<LLLLLLLL",payload_virtualSize,payload_virtualAddress,payload_rawSize,payload_rawAddress,0,0,0,payload_characterstics)
        newsize=payload_virtualAddress+payload_virtualSize
        noSections+=1
        with open("./bin/pay.txt","rb") as payload:
            pdata=payload.read()


        print("Section Header:"," ".join([str(hex(x))[2:] for x in sectionheader]),"\nSection Header Length:",len(sectionheader),"( "+str(hex(len(sectionheader)))+" )","\nNew file size:",newsize,"(",hex(newsize),")","\nNo of sections(updated):",noSections)
        print("=====================================================")
        
        writeDword(peoffset+0x50,newsize) # Optional Hdr. Size of Image (메모리 로딩되었을 때 전체 크기 변경)
        writeWord(peoffset+0x06,noSections) # File Hdr. Sections Count (섹션의 갯수 변경)
        writeData(lastSoffset+0x28,sectionheader) # 새로 만든 섹션 offset에 섹션 Header 정보 삽입

        
        '''''' # Data Directory 값 맞춰 쓰기
        # 여기에 directory 섹션 값 변경하여 덮어쓰기 코드 작성? 확인해볼 것
        writeDword(peoffset+0x58,0) #checksum값 0으로 변경
        #print(tdata[peoffset+0x58:peoffset+0x58+0x04]) # checksum값 변경된거 확인 test
        writeDword(peoffset+0x90, payload_virtualAddress + ((0x1*0x8) +(0x1*0x8)+(0x1*0x8)))#dll정보 offset) # dll정보 offset = (원본 API 개수 * 8byte) + ((모든 API 개수 *8byte) + (dll개수*8)) (Import Directory Addr. 부분)
        writeDword(peoffset +0x90+0x04 , (0x5*0x4))#dll정보 크기) # dll정보 크기 = ((imports 객체 갯수(5개) * 4byte) * (dll 갯수 + 1)) (Import Directory Size부분)
        # 새로운 섹션에 dll 이름 정보와 api 이름 정보 삽입

        ''''''
        
        pdata=pdata+b"\x00"*(payload_rawSize-len(pdata)) # 넣을 데이터 저장 (넣을 데이터 + 나머지 크기는 \x00으로 채우기)
        tdata=tdata+pdata # 전체 데이터에서 마지막부분에 데이터 추가
        

        newname="originalAPI.exe"

        if os.path.exists("dumpfile"):
            os.remove("dumpfile")

        with open(newname,"wb") as outfile:
            outfile.write(tdata)
        
        print("success")
