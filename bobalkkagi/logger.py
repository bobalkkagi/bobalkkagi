from unicorn import *
from unicorn.x86_const import *
from globalValue import get_queue, GLOBAL_VAR
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from util import IsReadable

import logging
import struct
import os

regis = {
    "RAX": UC_X86_REG_RAX,
    "RBX": UC_X86_REG_RBX,
    "RCX": UC_X86_REG_RCX,
    "RDX": UC_X86_REG_RDX,
    "RBP": UC_X86_REG_RBP,
    "RSP": UC_X86_REG_RSP,
    "RDI": UC_X86_REG_RDI,
    "RSI": UC_X86_REG_RSI,
    "R8": UC_X86_REG_R8, 
    "R9": UC_X86_REG_R9,
    "R10": UC_X86_REG_R10,
    "R11": UC_X86_REG_R11,
    "R12": UC_X86_REG_R12,
    "R13": UC_X86_REG_R13,
    "R14": UC_X86_REG_R14,
    "R15": UC_X86_REG_R15,
    "RIP": UC_X86_REG_RIP,
    "RFLAG": UC_X86_REG_EFLAGS
    }

def disas(code, address):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    assem = md.disasm(code, address)
    return assem


def setup_logger(uc, logger: logging.Logger, verbose:bool) -> None:
    
    if verbose:
        logLevel = logging.DEBUG
    else:
        logLevel = logging.INFO

    logger.setLevel(logLevel)
    # Create a console handler with a higher log level
    streamHandler = logging.StreamHandler()
    streamHandler.setLevel(logLevel)
    streamHandler.setFormatter(CustomFormatter(uc))
    logger.addHandler(streamHandler)
    
    # Save log file
    if not os.path.isdir('log'):
        os.mkdir('log')
    logFile = GLOBAL_VAR.ProtectedFile.split('\\')[-1].split('.')[0] + '_log.txt'
    fileHandler = logging.FileHandler(f"log\\{logFile}")
    logger.addHandler(fileHandler)

class CustomFormatter(logging.Formatter):
    uc :int
    reg= {}
    FORMATS : dict
    grey = "\x1b[38;20m"
    green = "\x1b[1;32m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    blue = "\x1b[34;40m"
    sky_blue="\x1b[36;40m"
    reset = "\x1b[0m"
    format_problem_str = "%(levelname)s - %(message)s"
    def __init__(self, uc):
        self.uc=uc
    
    def format(self, record: logging.LogRecord) -> str:

        for key in regis:
            tmp = self.uc.reg_read(regis[key])
            self.reg[key]=tmp
        
        d_format = self.blue+  "{0:=^80}\n".format("[ REGISTERS ]") + self.reset
        for idx, key in enumerate(self.reg):
            try:
                string = str(self.uc.mem_read(self.reg[key], 0x50).split(b'\x00')[0],'utf-8').replace('\n','')
                d_format += self.green+"%-10s" % (key+":")+self.reset+ "{:<016x}\t".format(self.reg[key])
                if IsReadable(string):
                    d_format += string + '\n'
                else:
                    d_format += '\n'
            except:
                d_format += self.green+"%-10s" % (key+":")+self.reset+ "0x%x\n" % self.reg[key]
            if key == "RFLAG":
                OF = (self.reg[key] & 0b100000000000) >> 11    #11 
                DF = (self.reg[key] & 0b10000000000 ) >> 10    #10 
                IF = (self.reg[key] & 0b1000000000  ) >> 9     #9 
                TF = (self.reg[key] & 0b100000000   ) >> 8     #8 
                SF = (self.reg[key] & 0b10000000    ) >> 7     #7 
                ZF = (self.reg[key] & 0b1000000     ) >> 6     #6 
                AF = (self.reg[key] & 0b10000       ) >> 4     #4 
                PF = (self.reg[key] & 0b100         ) >> 2     #2
                CF = (self.reg[key] & 0b1           )          #0
                d_format += f"\n    ZF {ZF} PF {PF} AF {AF}\n    OF {OF} SF {SF} DF {DF}\n    CF {CF} TF {TF} IF {IF}\n"
            if idx in [7, 15, 16]:
                d_format += '\n'


        d_format += self.reset
        d_format += self.blue + "{0:=^80}\n".format("[ DISASM ]") + self.reset
        
        for instruction in reversed(get_queue()):
            address = list(instruction.keys())[0]
            size = instruction[address]
            address = int(address,16)
            if(address == self.reg["RIP"]):
                d_format += self.green +"▶"+self.reset

            code = self.uc.mem_read(address, size)
            asm = disas(bytes(code), address)
            for a in asm:
                d_format +=" 0x%016x: " % a.address +self.green+"\t{0:<8}".format(a.mnemonic) + self.sky_blue+"\t{0:<}\n".format(a.op_str) + self.reset

        d_format += self.blue + "{0:=^80}\n".format("[ STACK ]") + self.reset

        
        stack =struct.unpack('<Q',self.uc.mem_read(self.reg["RSP"],0x8))[0]
        for i in range(-5,11):
            if i == 0:
                d_format += self.green +"▶"+self.yellow+"0x%x" % (self.reg["RSP"]) + self.green+"\t<==" \
                    + self.reset+ "\t0x%x\n" % (struct.unpack('<Q',self.uc.mem_read(self.reg["RSP"],0x8))[0])
            else:
                d_format += self.yellow+"0x%x" % (self.reg["RSP"]+8*i) + self.green+"\t<==" \
                    + self.reset+ "\t0x%x\n" % (struct.unpack('<Q',self.uc.mem_read(self.reg["RSP"]+8*i,0x8))[0])
        
        self.FORMATS = {
            logging.DEBUG: self.green + "%(levelname)s - %(message)s\n"+d_format +self.reset,
            logging.INFO: self.green + "%(levelname)s" + self.yellow + " - %(message)s"+self.reset,
            logging.WARNING: self.green + "HOOKING" + self.bold_red + " - %(message)s"+self.reset,
            logging.ERROR: self.red + self.format_problem_str + self.reset,
            logging.CRITICAL: self.bold_red + self.format_problem_str + self.reset
        }
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)
