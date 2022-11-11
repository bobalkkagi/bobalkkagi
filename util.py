from config import GlobalVar
import pefile
import sys


def calc_export_offset_of_dll(dllpath, function_name):
    """This function calculates the offset of exported function of a DLL. It is slow, so hardcoded values are used"""
    with open(dllpath, 'rb') as rf:
        dll = pefile.PE(data=rf.read())
    exports = dll.DIRECTORY_ENTRY_EXPORT.symbols
    for e in exports:
        if e.name == bytes(function_name, 'ascii'):
            return e.address
    return None

def getVirtualMemorySize(pe):
    sections = pe.sections
    min_offset = sys.maxsize
    total_size = 0
    for sec in sections:
        if sec.VirtualAddress < min_offset:
            min_offset = sec.VirtualAddress
        total_size += sec.Misc_VirtualSize
    total_size += min_offset
    return total_size

def align(value, page_size=4096):
    m = value % page_size
    f = page_size - m
    aligned_size = value + f
    return aligned_size

def merge(ranges):
    if not ranges:
        return []
    saved = list(ranges[0])
    for lower, upper in sorted([sorted(t) for t in ranges]):
        if lower <= saved[1] + 1:
            saved[1] = max(saved[1], upper)
        else:
            yield tuple(saved)
            saved[0] = lower
            saved[1] = upper
    yield tuple(saved)

def printHex(addr):
    print(hex(addr))

def alloc(uc, size, log, offset = None):
    page_size = 4 * 1024
    aligned_size = align(size, page_size)
    if offset is None:
        for chunk_start, chunk_end in GlobalVar['allocated_chunks']:
            if chunk_start <= GlobalVar['DynamicMemOffset'] <= chunk_end:
                GlobalVar['DynamicMemOffset'] = chunk_end + 1
        offset = GlobalVar['DynamicMemOffset']
        GlobalVar['DynamicMemOffset'] += aligned_size
    #new_offset_memory = offset % page_size
    aligned_address = offset

    if aligned_address % page_size != 0:
        aligned_address = align(offset)
    
    mapped_partial = False
    for chunk_start, chunk_end in GlobalVar['allocated_chunks']:
        if chunk_start <= aligned_address < chunk_end:
            log.info("Already fully mapped")
        else:
            log.info(f"Mapping missing piece 0x{chunk_end + 1:02x} to 0x{aligned_address + aligned_size:02x}")
            uc.mem_map(chunk_end, aligned_address + aligned_size - chunk_end)
        mapped_partial = True
        break

    if not mapped_partial:
        uc.mem_map(aligned_address, aligned_size)

    log.info(f"\tfrom 0x{aligned_address:02x} to 0x{(aligned_address + aligned_size):02x}")
    GlobalVar['allocated_chunks'] = list( merge(GlobalVar['allocated_chunks'] + [(aligned_address, aligned_address + aligned_size)]))
    GlobalVar['alloc_sizes'][aligned_address] = aligned_size

    return aligned_address