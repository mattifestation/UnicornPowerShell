$UC_ARCH = psenum $Mod UnicornEngine.Const.uc_arch UInt32 @{
    ARCH_ARM = 1      # ARM architecture (including Thumb Thumb-2)
    ARCH_ARM64 = 2    # ARM-64 also called AArch64
    ARCH_MIPS = 3     # Mips architecture
    ARCH_X86 = 4      # X86 architecture (including x86 & x86-64)
    #ARCH_PPC = 5     # PowerPC architecture. Not currently supported
    ARCH_SPARC = 6    # Sparc architecture
    ARCH_M68K = 7     # M68K architecture
}


$UC_MODE = psenum $Mod UnicornEngine.Const.Mode.X86 UInt32 @{
    MODE_16 = 2                  # 16-bit mode (X86)
    MODE_32 = 4                  # 32-bit mode (X86)
    MODE_64 = 8                  # 64-bit mode (X86 PPC)
}

$UC_MODE = psenum $Mod UnicornEngine.Const.Mode.Arm UInt32 @{
    MODE_ARM = 0                 # 32-bit ARM
    MODE_THUMB = 16              # ARM's Thumb mode including Thumb-2
    MODE_V8 = 64                 # ARMv8 A32 encodings for ARM
}

$UC_MODE = psenum $Mod UnicornEngine.Const.Mode.Arm64 UInt32 @{
    MODE_ARM = 0                 # 32-bit ARM
    MODE_V8 = 64                 # ARMv8 A32 encodings for ARM
    MODE_MCLASS = 32             # ARM's Cortex-M series
}

$UC_MODE = psenum $Mod UnicornEngine.Const.Mode.Sparc UInt32 @{
    MODE_32 = 4                  # 32-bit mode (X86)
    MODE_V9 = 16                 # SparcV9 mode (Sparc)
}

$UC_MODE = psenum $Mod UnicornEngine.Const.Mode.Mips UInt32 @{
    MODE_MIPS32 = 4              # Mips32 ISA (Mips)
    MODE_MIPS64 = 8              # Mips64 ISA (Mips)
    MODE_MIPS32BE = 1073741828   # Mips32 ISA (Mips) Big Endian
    MODE_MIPS64BE = 1073741832   # Mips64 ISA (Mips) Big Endian
    #MODE_MICRO = 16              # MicroMips mode (MIPS)
    #MODE_MIPS3 = 32              # Mips III ISA
    #MODE_MIPS32R6 = 64           # Mips32r6 ISA
}

$UC_PROT = psenum $Mod UnicornEngine.Const.uc_prot UInt32 @{
    READ = 1
    WRITE = 2
    EXECUTE = 4
    ALL = 7
} -Bitfield

$UC_ERR = psenum $Mod UnicornEngine.Const.uc_err UInt32 @{
    OK = 0               # No error: everything was fine
    NOMEM = 1            # Out-Of-Memory error: uc_open() uc_emulate()
    ARCH = 2             # Unsupported architecture: uc_open()
    HANDLE = 3           # Invalid handle
    MODE = 4             # Invalid/unsupported mode: uc_open()
    VERSION = 5          # Unsupported version (bindings)
    READ_UNMAPPED = 6    # Quit emulation due to READ on unmapped memory: uc_emu_start()
    WRITE_UNMAPPED = 7   # Quit emulation due to WRITE on unmapped memory: uc_emu_start()
    FETCH_UNMAPPED = 8   # Quit emulation due to FETCH on unmapped memory: uc_emu_start()
    HOOK = 9             # Invalid hook type: uc_hook_add()
    INSN_INVALID = 10    # Quit emulation due to invalid instruction: uc_emu_start()
    MAP = 11             # Invalid memory mapping: uc_mem_map()
    WRITE_PROT = 12      # Quit emulation due to UC_MEM_WRITE_PROT violation: uc_emu_start()
    READ_PROT = 13       # Quit emulation due to UC_MEM_READ_PROT violation: uc_emu_start()
    FETCH_PROT = 14      # Quit emulation due to UC_MEM_FETCH_PROT violation: uc_emu_start()
    ARG = 15             # Inavalid argument provided to uc_xxx function (See specific function API)
    READ_UNALIGNED = 16  # Unaligned read
    WRITE_UNALIGNED = 17 # Unaligned write
    FETCH_UNALIGNED = 18 # Unaligned fetch
    HOOK_EXIST = 19      # hook for this event already existed
    RESOURCE = 20        # Insufficient resource: uc_emu_start()
}

$UC_HOOK = psenum $Mod UnicornEngine.Const.uc_hook_type UInt32 @{
    INTR = 1
    INSN = 2
    CODE = 4
    BLOCK = 8
    MEM_READ_UNMAPPED = 16
    MEM_WRITE_UNMAPPED = 32
    MEM_FETCH_UNMAPPED = 64
    MEM_READ_PROT = 128
    MEM_WRITE_PROT = 256
    MEM_FETCH_PROT = 512
    MEM_READ = 1024
    MEM_WRITE = 2048
    MEM_FETCH = 4096
    MEM_UNMAPPED = 112
    MEM_PROT = 896
    MEM_READ_INVALID = 144
    MEM_WRITE_INVALID = 288
    MEM_FETCH_INVALID = 576
    MEM_INVALID = 1008
}

$UC_MEM = psenum $Mod UnicornEngine.Const.uc_mem UInt32 @{
    READ = 16
    WRITE = 17
    FETCH = 18
    READ_UNMAPPED = 19
    WRITE_UNMAPPED = 20
    FETCH_UNMAPPED = 21
    WRITE_PROT = 22
    READ_PROT = 23
    FETCH_PROT = 24
}