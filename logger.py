from unicorn import *
from unicorn.x86_const import *
import logging
import config
import struct
from capstone import *
import sys
import lief  # type: ignore

regis = {
    "RAX": UC_X86_REG_RAX,
    "RBX": UC_X86_REG_RBX,
    "RCX": UC_X86_REG_RCX,
    "RDX": UC_X86_REG_RDX,
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
    "RBP": UC_X86_REG_RBP,
    "RSP": UC_X86_REG_RSP,
    "RIP": UC_X86_REG_RIP
    }

def PrintFunction(log, uc=None):
    if uc:
        log.info(f"call {sys._getframe(1).f_code.co_name} RAX : {uc.reg_read(UC_X86_REG_RAX)}")
    else:
        log.info(f"call {sys._getframe(1).f_code.co_name}")

def disas(code,address):
    md=Cs(CS_ARCH_X86,CS_MODE_64)
    assem=md.disasm(code,address)
    return assem

def setup_logger(uc,logger: logging.Logger, verbose:bool) -> None:
    
    lief.logging.disable()
    if verbose:
        logLevel = logging.DEBUG
    else:
        logLevel = logging.INFO


    logger.setLevel(logging.DEBUG)

    # Create a console handler with a higher log level
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.DEBUG)
    stream_handler.setFormatter(CustomFormatter(uc))
    logger.addHandler(stream_handler)


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

        d_format = self.blue+"--------------------------[ REGISTERS]-------------------------\n"+self.reset
        for key in self.reg:
            d_format += self.green+"%-10s" % (key+":")+self.reset+ "0x{:016x}\n".format(self.reg[key])
        d_format += self.reset
        d_format += self.blue+"--------------------------[ DISASM ]-------------------------\n"+self.reset
        
        for instruction in reversed(config.get_queue()):
            address = list(instruction.keys())[0]
            size = instruction[address]
            address = int(address,16)
            if(address == self.reg["RIP"]):
                d_format += self.green +"▶"+self.reset

            code = self.uc.mem_read(address, size)
            asm=disas(bytes(code),address)
            for a in asm:
                d_format +="  0x%x: " % a.address +self.green+"\t%s" % a.mnemonic + self.sky_blue+"\t%s\n" % a.op_str + self.reset
        
        d_format += self.blue+"--------------------------[ STACK ]-------------------------\n"+self.reset

        
        stack =struct.unpack('<Q',self.uc.mem_read(self.reg["RSP"],0x8))[0]
        for i in range(-5,11):
            d_format += self.yellow+"0x{:016x}".format(self.reg["RSP"]+8*i) + self.green+"\t<==" + self.reset+ "\t0x%x\n" % (struct.unpack('<Q',self.uc.mem_read(self.reg["RSP"]+8*i,0x8))[0])
        self.FORMATS = {
            #logging.DEBUG: self.grey + "%(levelname)s - %(message)s" + self.reset,
            logging.DEBUG: self.green + "%(levelname)s - %(message)s\n"+d_format +self.reset,
            logging.INFO: self.green + "%(levelname)s" + self.bold_red + " - %(message)s"+self.reset,
            logging.WARNING: self.yellow + self.format_problem_str + self.reset,
            logging.ERROR: self.red + self.format_problem_str + self.reset,
            logging.CRITICAL: self.bold_red + self.format_problem_str + self.reset
        }
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)