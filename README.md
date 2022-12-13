# TEAM Bobalkkagi

BOB11 project

Unpacking & Unwrapping & Devirtualization(Not yet) of Themida 3.1.3 packed program(Tiger red64)

### API Hook

Hooking API based win10_v1903  

## How to

### Install

```
pip install bobalkkagi
```
**or**

```
pip install git+https://github.com/hackerhoon/bobalkkagi.git
```

### Notes

Need default Dll folder(win10_v1903) or you can give dll folder path

win10_v1903 folder is in https://github.com/hackerhoon/bobalkkagi

### Use
```
NAME
    bobalkkagi

SYNOPSIS
    bobalkkagi PROTECTEDFILE <flags>

POSITIONAL ARGUMENTS
    PROTECTEDFILE
        Type: str

FLAGS
    --mode=MODE
        Type: str
        Default: 'f'
    --verbose=VERBOSE
        Type: str
        Default: 'f'
    --dllPath=DLLPATH
        Type: str
        Default: 'win10_v1903'
    --oep=OEP
        Type: str
        Default: 't'
    --debugger=DEBUGGER
        Type: str
        Default: 'f'

NOTES
    You can also use flags syntax for POSITIONAL ARGUMENTS

```

### Option Description

#### Mode: f[fast], c[hook_code], b[hook_block] 

Description: Mean emulating mode, we implement necessary api to unpack protected excutables by themida 3.1.3. 

Running on **fast mode** compare rip with only hook API function area size 32(0x20), but **hook_block mode** and **hook_code mode** compare rip with all mapped DLL memory (min 0x1000000) to check functions. block mode emulate block size(call, jmp) code mode do it opcode by opcode.

#### verbose

**verbose** show Loaded DLL on memory, we will update it to turn on/off HOOKING API CALL info.

#### dllPath

**dllPath** is directory where DLLs to load on memory exists. DLLs are different for each window version. 
This tool may be not working with your window DLL path(C:\Windows\System32)

#### oep

**oep** is option to find original entry point. If you turn off this option, you can emulate program after oep**(fast mode can't do it, it works on hook_block and hook_code)**

#### debugger

If you want unpack another protector or different version of themida, you should add necessary hook_api functions(anti debugging, handle, syscall). you can analyze protected program hook_code mode or hook_block mode(more detail in https://github.com/unicorn-engine/unicorn) with **debugger ** option**(working only hook_code mode!)**





