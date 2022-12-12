# TEAM Bobalkkagi

BOB11 project

Unpacking & Unwrapping & Devirtualization(Not yet) of Themida 3.1.3 packed program(Tiger red64)

### Feature

Hooking api based win10_v1903  

## How to

### Install

```
pip install bobalkkagi
```
or
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

