#region environment setup
function Invoke-LoadLibrary {
<#
.SYNOPSIS

Loads a DLL into the current PowerShell process.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Invoke-LoadLibrary is a simple wrapper for kernel32!LoadLibrary
designed primarily for malware analysis the output of which can be
consumed by New-DllExportFunction.

.PARAMETER FileName

Specifies the name of the module to load. If the string specifies a
relative path or a module name without a path, the function uses a
standard search strategy to find the module. See the MSDN
documentation on LoadLibrary for more information on DLL search
paths.

.EXAMPLE

Invoke-LoadLibrary -FileName C:\temp\evil.dll

.EXAMPLE

'kernel32', 'ntdll' | Invoke-LoadLibrary

.INPUTS

System.String

Invoke-LoadLibrary accepts one or more module names to load over the
pipeline.

.OUTPUTS

System.Diagnostics.ProcessModule
#>

    [OutputType([Diagnostics.ProcessModule])]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FileName
    )

    BEGIN {
        $SafeNativeMethods = $null
        $LoadLibrary = $null

        # System.Uri and Microsoft.Win32.SafeNativeMethods are both
        # contained within System.dll. [Uri] is public though.
        # Microsoft.Win32.SafeNativeMethods is a NonPublic class.
        $UnmanagedClass = 'Microsoft.Win32.SafeNativeMethods'
        $SafeNativeMethods = [Uri].Assembly.GetType($UnmanagedClass)

        # Perform additional error handling since we're borrowing LoadLibrary
        # from a NonPublic class. Technically, Microsoft could change this
        # interface at any time.
        if ($SafeNativeMethods -eq $null) {
            throw 'Unable to get a reference to the ' +
                  'Microsoft.Win32.SafeNativeMethods within System.dll.'
        }

        $LoadLibrary = $SafeNativeMethods.GetMethod('LoadLibrary')

        if ($LoadLibrary -eq $null) {
            throw 'Unable to get a reference to LoadLibrary within' +
                  'Microsoft.Win32.SafeNativeMethods.'
        }
    }

    PROCESS {
        $LoadedModuleInfo = $null

        $LibAddress = $LoadLibrary.Invoke($null, @($FileName))
        $Exception = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

        if ($LibAddress -eq [IntPtr]::Zero) {
            $Exception = New-Object ComponentModel.Win32Exception($Exception)
            throw $Exception.Message
        }

        $IntPtrPrintWidth = "X$([IntPtr]::Size * 2)"

        Write-Verbose "$FileName loaded at 0x$(($LibAddress).ToString($IntPtrPrintWidth))"

        $CurrentProcess = Get-Process -Id $PID

        $LoadedModuleInfo = $CurrentProcess.Modules |
            Where-Object { $_.BaseAddress -eq $LibAddress }

        if ($LoadedModuleInfo -eq $null) {
            throw 'Unable to obtain loaded module information for ' +
                "$FileName. The module was likely already unloaded."
        }

        return $LoadedModuleInfo
    }
}

$Mod = New-InMemoryModule -ModuleName UnicornAssembly

# Load arch specific types
Get-ChildItem "$PSScriptRoot\Const" -Filter *.ps1 | ForEach-Object { . $_.FullName }

$FunctionDefinitions = @(
    (func kernel32 SetDllDirectory ([Bool]) @([String])),
    (func unicorn uc_version ([Int]) @([UInt32].MakeByRefType(), [UInt32].MakeByRefType())),
    (func unicorn uc_strerror ([IntPtr]) @($UC_ERR)),
    (func unicorn uc_open ($UC_ERR) @($UC_ARCH, [UInt32], [IntPtr].MakeByRefType())),
    (func unicorn uc_close ($UC_ERR) @([IntPtr])),
    (func unicorn uc_mem_map ($UC_ERR) @([IntPtr], [UInt64], [UInt32], $UC_PROT)),
    (func unicorn uc_mem_protect ($UC_ERR) @([IntPtr], [UInt64], [UInt32], $UC_PROT)),
    (func unicorn uc_mem_unmap ($UC_ERR) @([IntPtr], [UInt64], [UInt32])),
    (func unicorn uc_mem_write ($UC_ERR) @([IntPtr], [UInt64], [Byte[]], [Int32])),
    (func unicorn uc_mem_read ($UC_ERR) @([IntPtr], [UInt64], [Byte[]], [UInt32])),
    (func unicorn uc_reg_write ($UC_ERR) @([IntPtr], [UInt32], [Int64].MakeByRefType())),
    (func unicorn uc_reg_read ($UC_ERR) @([IntPtr], [UInt32], [Int64].MakeByRefType())),
    (func unicorn uc_emu_start ($UC_ERR) @([IntPtr], [UInt64], [UInt64], [UInt64], [UInt32])),
    (func unicorn uc_emu_stop ($UC_ERR) @([IntPtr])),
    (func unicorn uc_hook_del ($UC_ERR) @([IntPtr], [IntPtr])),
    (func unicorn uc_hook_add_noargs ($UC_ERR) @([IntPtr], [IntPtr].MakeByRefType(), $UC_HOOK, [MulticastDelegate], [IntPtr]) -EntryPoint 'uc_hook_add'),
    (func unicorn uc_hook_add_arg0 ($UC_ERR) @([IntPtr], [IntPtr].MakeByRefType(), $UC_HOOK, [MulticastDelegate], [IntPtr], [UInt64]) -EntryPoint 'uc_hook_add'),
    (func unicorn uc_hook_add_arg0_arg1 ($UC_ERR) @([IntPtr], [IntPtr].MakeByRefType(), $UC_HOOK, [MulticastDelegate], [IntPtr], [UInt64], [UInt64]) -EntryPoint 'uc_hook_add')
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'UnicornEngine.NativeMethods'

# The full path to the Unicorn Engine DLL and dependencies
$LibPath = Join-Path $PSScriptRoot "Lib\Unicorn"

# Depending upon the bitness of PowerShell, point to the correct arch directory
$Arch = '86'
if ([IntPtr]::Size -eq 8) { $Arch = '64' }

$ArchLibPath = "$LibPath\x$Arch"
$UnicornDllPath = Join-Path $ArchLibPath 'unicorn.dll'

if ([UnicornEngine.NativeMethods.kernel32]::SetDllDirectory($ArchLibPath) -eq $False) {
    throw 'Unable to set Unicorn Engine library path.'
}

$LoadedUnicornLib = Invoke-LoadLibrary -FileName $UnicornDllPath
#endregion


#region private function definitions
function ConvertFrom-UCErrorCode {
    [OutputType([String])]
    param (
        [Parameter(Mandatory = $True)]
        [UnicornEngine.Const.uc_err]
        [ValidateScript({ [Enum]::IsDefined($_.GetType(), $_) })]
        $ErrorCode
    )

    $ErrorMessagePtr = [UnicornEngine.NativeMethods.unicorn]::uc_strerror($ErrorCode)


    $ErrorMessage = ''

    if ($ErrorMessagePtr -ne [IntPtr]::Zero) {
        $ErrorMessage = [Runtime.InteropServices.Marshal]::PtrToStringAnsi($ErrorMessagePtr)
    } else {
        throw 'Unable to obtain an error string.'
    }

    return $ErrorMessage
}

function Assert-UCError {
    param (
        [Parameter(Mandatory = $True)]
        [UnicornEngine.Const.uc_err]
        [ValidateScript({ [Enum]::IsDefined($_.GetType(), $_) })]
        $ErrorCode,

        [Management.Automation.InvocationInfo]
        $Context
    )

    if ($ErrorCode -ne [UnicornEngine.Const.uc_err]::OK) {
        $ContextMessage = ''

        if ($PSBoundParameters['Context']) {
            $ContextMessage = "$($Context.InvocationName): "
        }

        $ErrorMessage = ConvertFrom-UCErrorCode -ErrorCode $ErrorCode

        throw "$($ContextMessage)$ErrorMessage"
    }
}

# This is a heavily modified version of Oisin Grehan's New-ScriptBlockCallback function.
# Thank you to Oisin (@oising) for providing the syntax for customized callback function signatures!
# Todo: Rewrite this using reflection versus calling Add-Type.
function New-UCHookCallback {
    param(
        [Parameter(Mandatory = $True, ParameterSetName = 'CodeHook')]
        [Switch]
        $CodeHook,

        [Parameter(Mandatory = $True, ParameterSetName = 'InterruptHook')]
        [Switch]
        $InterruptHook,

        [Parameter(Mandatory = $True, ParameterSetName = 'BlockHook')]
        [Switch]
        $BasicBlockHook,

        [Parameter(Mandatory = $True, ParameterSetName = 'ReadMemHook')]
        [Switch]
        $MemoryReadHook,

        [Parameter(Mandatory = $True, ParameterSetName = 'WriteMemHook')]
        [Switch]
        $MemoryWriteHook,

        [Parameter(Mandatory = $True, ParameterSetName = 'InvalidMemHook')]
        [Switch]
        $InvalidMemAccessHook,

        [Parameter(Mandatory = $True, ParameterSetName = 'SyscallHook')]
        [Switch]
        $SyscallHook,

        [Parameter(Mandatory = $True, ParameterSetName = 'InHook')]
        [Switch]
        $X86InHook,

        [Parameter(Mandatory = $True, ParameterSetName = 'OutHook')]
        [Switch]
        $X86OutHook,

        [parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $Action
    )
  
    if (-not ('CodeHookEventBridge' -as [Type])) {
        Add-Type @'
            using System;
            using System.Runtime.InteropServices;

            public sealed class CodeBlockHookEventBridge
            {
                [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
                public delegate void Handler(IntPtr SessionHandle, UInt64 Address, UInt32 Size, IntPtr UserData);

                public event Handler CallbackComplete = delegate { };

                private CodeBlockHookEventBridge() {}

                private void CallbackInternal(IntPtr SessionHandle, UInt64 Address, UInt32 Size, IntPtr UserData)
                {
                    CallbackComplete(SessionHandle, Address, Size, UserData);
                }

                public Handler Callback
                {
                    get { return new Handler(CallbackInternal); }
                }

                public static CodeBlockHookEventBridge Create()
                {
                    return new CodeBlockHookEventBridge();
                }
            }

            public sealed class InterruptHookEventBridge
            {
                [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
                public delegate void Handler(IntPtr SessionHandle, UInt32 InterruptNumber, IntPtr UserData);

                public event Handler CallbackComplete = delegate { };

                private InterruptHookEventBridge() {}

                private void CallbackInternal(IntPtr SessionHandle, UInt32 InterruptNumber, IntPtr UserData)
                {
                    CallbackComplete(SessionHandle, InterruptNumber, UserData);
                }

                public Handler Callback
                {
                    get { return new Handler(CallbackInternal); }
                }

                public static InterruptHookEventBridge Create()
                {
                    return new InterruptHookEventBridge();
                }
            }

            public sealed class MemReadWriteHookEventBridge
            {
                [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
                public delegate void Handler(IntPtr SessionHandle, int MemType, UInt64 Address, int Size, Int64 Value, IntPtr UserData);

                public event Handler CallbackComplete = delegate { };

                private MemReadWriteHookEventBridge() {}

                private void CallbackInternal(IntPtr SessionHandle, int MemType, UInt64 Address, int Size, Int64 Value, IntPtr UserData)
                {
                    CallbackComplete(SessionHandle, MemType, Address, Size, Value, UserData);
                }

                public Handler Callback
                {
                    get { return new Handler(CallbackInternal); }
                }

                public static MemReadWriteHookEventBridge Create()
                {
                    return new MemReadWriteHookEventBridge();
                }
            }

            public sealed class InHookEventBridge
            {
                [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
                public delegate void Handler(IntPtr SessionHandle, UInt32 Port, int Size, IntPtr UserData);

                public event Handler CallbackComplete = delegate { };

                private InHookEventBridge() {}

                private void CallbackInternal(IntPtr SessionHandle, UInt32 Port, int Size, IntPtr UserData)
                {
                    CallbackComplete(SessionHandle, Port, Size, UserData);
                }

                public Handler Callback
                {
                    get { return new Handler(CallbackInternal); }
                }

                public static InHookEventBridge Create()
                {
                    return new InHookEventBridge();
                }
            }

            public sealed class OutHookEventBridge
            {
                [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
                public delegate void Handler(IntPtr SessionHandle, UInt32 Port, int Size, UInt32 Value, IntPtr UserData);

                public event Handler CallbackComplete = delegate { };

                private OutHookEventBridge() {}

                private void CallbackInternal(IntPtr SessionHandle, UInt32 Port, int Size, UInt32 Value, IntPtr UserData)
                {
                    CallbackComplete(SessionHandle, Port, Size, Value, UserData);
                }

                public Handler Callback
                {
                    get { return new Handler(CallbackInternal); }
                }

                public static OutHookEventBridge Create()
                {
                    return new OutHookEventBridge();
                }
            }

            public sealed class SyscallHookEventBridge
            {
                [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
                public delegate void Handler(IntPtr SessionHandle, IntPtr UserData);

                public event Handler CallbackComplete = delegate { };

                private SyscallHookEventBridge() {}

                private void CallbackInternal(IntPtr SessionHandle, IntPtr UserData)
                {
                    CallbackComplete(SessionHandle, UserData);
                }

                public Handler Callback
                {
                    get { return new Handler(CallbackInternal); }
                }

                public static SyscallHookEventBridge Create()
                {
                    return new SyscallHookEventBridge();
                }
            }
'@
    }

    switch ($PSCmdlet.ParameterSetName) {
        'CodeHook' {
            $Bridge = [CodeBlockHookEventBridge]::Create()
        }

        'BlockHook' {
            $Bridge = [CodeBlockHookEventBridge]::Create()
        }

        'InterruptHook' {
            $Bridge = [InterruptHookEventBridge]::Create()
        }

        'ReadMemHook' {
            $Bridge = [MemReadWriteHookEventBridge]::Create()
        }

        'WriteMemHook' {
            $Bridge = [MemReadWriteHookEventBridge]::Create()
        }

        'InvalidMemHook' {
            $Bridge = [MemReadWriteHookEventBridge]::Create()
        }

        'InHook' {
            $Bridge = [InHookEventBridge]::Create()
        }

        'OutHook' {
            $Bridge = [OutHookEventBridge]::Create()
        }

        'SyscallHook' {
            $Bridge = [SyscallHookEventBridge]::Create()
        }
    }

    $null = Register-ObjectEvent -InputObject $Bridge -EventName CallbackComplete -Action $Action -MessageData $args
    $Bridge.Callback
}
#endregion


#region public function definitions
function Get-UCVersion {
<#
.SYNOPSIS

Returns the version of the Unicorn Engine.

.DESCRIPTION

Get-UCVersion returns the version of the Unicorn Engine in unicorn.dll. Tests should call this function to validate that the version of unicorn.dll matches the version that you expect to support.

.INPUTS

None

.OUTPUTS

System.Version

Outputs the version of the Unicorn Engine.
#>

    [OutputType([Version])]
    param ()

    $Major = 0
    $Minor = 0

    $null = [UnicornEngine.NativeMethods.unicorn]::uc_version([Ref] $Major, [Ref] $Minor)

    $CombinedVersion = New-Object Version($Major, $Minor, 0, 0)

    return $CombinedVersion
}

function New-UCEmulatorSession {
<#
.SYNOPSIS

Establishes a new Unicorn emulator session.

.DESCRIPTION

New-UCEmulatorSession establishes a new Unicorn emulator session for a specific processor architecture. The session object returned from New-UCEmulatorSession is required for all subsequent emulator functions. When an emulator session is complete, the session object should be passed to Remove-UCEmulatorSession.

.PARAMETER Architecture

Specifies the processor archtecture to be emulated.

.PARAMETER Mode

Specifies the processor hardware mode.

.EXAMPLE

$Session = New-UCEmulatorSession -X86 -X86Mode MODE_32

.EXAMPLE

$Session = New-UCEmulatorSession -X86 -X86Mode MODE_64

.EXAMPLE

$Session = New-UCEmulatorSession -Arm -ArmMode MODE_ARM

.EXAMPLE

$Session = New-UCEmulatorSession -Arm64 -Arm64Mode MODE_ARM

.EXAMPLE

$Session = New-UCEmulatorSession -M68K

.EXAMPLE

$Session = New-UCEmulatorSession -Sparc -SparcMode MODE_32

.EXAMPLE

$Session = New-UCEmulatorSession -Mips -MipsMode MODE_MIPS32

.INPUTS

None

.OUTPUTS

PSObject

Outputs an IntPtr representing the emulator handle.
#>

    [OutputType([IntPtr])]
    param (
        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'X86')]
        [Switch]
        $X86,

        [Parameter(Mandatory = $True, Position = 1, ParameterSetName = 'X86')]
        [UnicornEngine.Const.Mode.X86]
        $X86Mode,

        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'Arm')]
        [Switch]
        $Arm,

        [Parameter(Mandatory = $True, Position = 1, ParameterSetName = 'Arm')]
        [UnicornEngine.Const.Mode.Arm]
        $ArmMode,

        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'Arm64')]
        [Switch]
        $Arm64,

        [Parameter(Mandatory = $True, Position = 1, ParameterSetName = 'Arm64')]
        [UnicornEngine.Const.Mode.Arm64]
        $Arm64Mode,

        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'M68K')]
        [Switch]
        $M68K,

        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'Sparc')]
        [Switch]
        $Sparc,

        [Parameter(Mandatory = $True, Position = 1, ParameterSetName = 'Sparc')]
        [UnicornEngine.Const.Mode.Sparc]
        $SparcMode,

        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'Mips')]
        [Switch]
        $Mips,

        [Parameter(Mandatory = $True, Position = 1, ParameterSetName = 'Mips')]
        [UnicornEngine.Const.Mode.Mips]
        $MipsMode
    )

    switch ($PSCmdlet.ParameterSetName) {
        'X86' {
            $Architecture = [UnicornEngine.Const.uc_arch]::ARCH_X86
            $Mode = $X86Mode
        }

        'Arm' {
            $Architecture = [UnicornEngine.Const.uc_arch]::ARCH_ARM
            $Mode = $ArmMode
        }

        'Arm64' {
            $Architecture = [UnicornEngine.Const.uc_arch]::ARCH_ARM64
            $Mode = $Arm64Mode
        }

        'M68K' {
            $Architecture = [UnicornEngine.Const.uc_arch]::ARCH_M68K
            $Mode = [UnicornEngine.Const.Mode.X86]::MODE_32
        }

        'Sparc' {
            $Architecture = [UnicornEngine.Const.uc_arch]::ARCH_SPARC
            $Mode = $SparcMode
        }

        'Mips' {
            $Architecture = [UnicornEngine.Const.uc_arch]::ARCH_MIPS
            $Mode = $MipsMode
        }
    }

    $UCEngine = [IntPtr]::Zero

    $Status = [UnicornEngine.NativeMethods.unicorn]::uc_open($Architecture, $Mode, [Ref] $UCEngine)

    Assert-UCError -ErrorCode $Status -Context $MyInvocation

    if ($UCEngine -eq [IntPtr]::Zero) { throw 'Unable to obtain engine handle.' }

    return $UCEngine
}

function Initialize-UCMemoryMap {
<#
.SYNOPSIS

Map memory in for emulation.

.DESCRIPTION

Initialize-UCMemoryMap maps in a memory page of a specific size and protection for use by the emulator.

.PARAMETER Session

The Unicorn Engine emulator handle returned from New-UCEmulatorSession.

.PARAMETER Address

Specifies the starting address of the new memory region to be mapped in. This address must be aligned to 4KB.

.PARAMETER Size

Specifies the size of the new memory region to be mapped in. This size must be multiple of 4KB.

.PARAMETER Protection

Specifies the permissions for the newly mapped region. This must be some combination of READ | WRITE | EXECUTE | ALL (default)

.EXAMPLE

PS C:\>$Session = New-UCEmulatorSession -X86 -X86Mode MODE_32
PS C:\>$Session | Initialize-UCMemoryMap -Address 0x1000000 -Size (2 * 4KB)

.EXAMPLE

PS C:\>$Session = New-UCEmulatorSession -X86 -X86Mode MODE_32
PS C:\>$Session | Initialize-UCMemoryMap -Address 0x1000000 -Size (2 * 4KB) -Protection READ

.EXAMPLE

PS C:\>$Session = New-UCEmulatorSession -X86 -X86Mode MODE_32
PS C:\>$Session | Initialize-UCMemoryMap -Address 0x1000000 -Size (2 * 4KB) -Protection 'READ, WRITE'

.INPUTS

PSObject

You can pipe a Unicorn Engine session handle returned from New-UCEmulatorSession to Initialize-UCMemoryMap.

.OUTPUTS

None
#>

    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [IntPtr]
        [ValidateScript({ $_ -and ($_ -ne [IntPtr]::Zero) })]
        $Session,

        [Parameter(Mandatory = $True)]
        [UInt64]
        [ValidateScript({ $_ % 4KB -eq 0 })]
        $Address,

        [Parameter(Mandatory = $True)]
        [UInt32]
        [ValidateScript({ $_ % 4KB -eq 0 })]
        $Size,

        [UnicornEngine.Const.uc_prot]
        $Protection = [UnicornEngine.Const.uc_prot]::ALL
    )

    $Status = [UnicornEngine.NativeMethods.unicorn]::uc_mem_map($Session, $Address, $Size, $Protection)

    Assert-UCError -ErrorCode $Status -Context $MyInvocation
}

function Remove-UCMemoryMap {
<#
.SYNOPSIS

Unmap a region of emulation memory.

.DESCRIPTION

Remove-UCMemoryMap unmaps a previously mapped region of memory.

.PARAMETER Session

The Unicorn Engine emulator handle returned from New-UCEmulatorSession.

.PARAMETER Address

Specifies the address of the memory region to be unmapped. This address must be aligned to 4KB.

.PARAMETER Size

Specifies the size of the memory region to be unmapped. This size must be multiple of 4KB.

.EXAMPLE

PS C:\>$Session = New-UCEmulatorSession -X86 -X86Mode MODE_32
PS C:\>$Session | Initialize-UCMemoryMap -Address 0x1000000 -Size (2 * 4KB)
PS C:\>$Session | Remove-UCMemoryMap -Address 0x1000000 -Size (2 * 4KB)

.INPUTS

PSObject

You can pipe a Unicorn Engine session handle returned from New-UCEmulatorSession to Remove-UCMemoryMap.

.OUTPUTS

None
#>

    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [IntPtr]
        [ValidateScript({ $_ -and ($_ -ne [IntPtr]::Zero) })]
        $Session,

        [Parameter(Mandatory = $True)]
        [UInt64]
        [ValidateScript({ $_ % 4KB -eq 0 })]
        $Address,

        [Parameter(Mandatory = $True)]
        [UInt32]
        [ValidateScript({ $_ % 4KB -eq 0 })]
        $Size
    )

    $Status = [UnicornEngine.NativeMethods.unicorn]::uc_mem_unmap($Session, $Address, $Size)

    Assert-UCError -ErrorCode $Status -Context $MyInvocation
}

function Set-UCMemoryProtection {
<#
.SYNOPSIS

Set memory permissions for emulation memory.

.DESCRIPTION

Set-UCMemoryProtection changes permissions on an existing memory region.

.PARAMETER Session

The Unicorn Engine emulator handle returned from New-UCEmulatorSession.

.PARAMETER Address

Specifies the starting address of the memory region to be modified. This address must be aligned to 4KB.

.PARAMETER Size

Specifies the size of the memory region to be modified. This size must be multiple of 4KB.

.PARAMETER Protection

Specifies the new permissions for the mapped region. This must be some combination of READ | WRITE | EXECUTE | ALL (default)

.EXAMPLE

PS C:\>$Session = New-UCEmulatorSession -X86 -X86Mode MODE_32
PS C:\>$Session | Initialize-UCMemoryMap -Address 0x1000000 -Size (2 * 4KB) -Protection 'READ, WRITE'
PS C:\>$Session | Set-UCMemoryProtection -Address 0x1000000 -Size (2 * 4KB) -Protection EXECUTE

.INPUTS

PSObject

You can pipe a Unicorn Engine session handle returned from New-UCEmulatorSession to Initialize-UCMemoryMap.

.OUTPUTS

None
#>

    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [IntPtr]
        [ValidateScript({ $_ -and ($_ -ne [IntPtr]::Zero) })]
        $Session,

        [Parameter(Mandatory = $True)]
        [UInt64]
        [ValidateScript({ $_ % 4KB -eq 0 })]
        $Address,

        [Parameter(Mandatory = $True)]
        [UInt32]
        [ValidateScript({ $_ % 4KB -eq 0 })]
        $Size,

        [UnicornEngine.Const.uc_prot]
        $Protection = [UnicornEngine.Const.uc_prot]::ALL
    )

    $Status = [UnicornEngine.NativeMethods.unicorn]::uc_mem_protect($Session, $Address, $Size, $Protection)

    Assert-UCError -ErrorCode $Status -Context $MyInvocation
}

function Write-UCMemory {
<#
.SYNOPSIS

Write to a range of bytes in memory.

.DESCRIPTION

Write-UCMemory writes to a range of bytes previously mapped in memory with the Initialize-UCMemoryMap function.

.PARAMETER Session

The Unicorn Engine emulator handle returned from New-UCEmulatorSession.

.PARAMETER Address

Specifies the starting memory address of bytes to set.

.PARAMETER Data

Specifies the bytes to be written to memory.

.EXAMPLE

PS C:\>$Session = New-UCEmulatorSession -X86 -X86Mode MODE_32
PS C:\>$Session | Initialize-UCMemoryMap -Address 0x1000000 -Size (2 * 4KB)
PS C:\>$Session | Write-UCMemory -Address 0x1000000 -Data @(0x90, 0x90, 0x90)

.INPUTS

PSObject

You can pipe a Unicorn Engine session handle returned from New-UCEmulatorSession to Write-UCMemory.

.OUTPUTS

None    
#>

    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [IntPtr]
        [ValidateScript({ $_ -and ($_ -ne [IntPtr]::Zero) })]
        $Session,

        [Parameter(Mandatory = $True)]
        [UInt64]
        $Address,

        [Parameter(Mandatory = $True)]
        [Byte[]]
        [ValidateNotNullOrEmpty()]
        $Data
    )

    $Status = [UnicornEngine.NativeMethods.unicorn]::uc_mem_write($Session, $Address, $Data, $Data.Length)

    Assert-UCError -ErrorCode $Status -Context $MyInvocation
}

function Read-UCMemory {
<#
.SYNOPSIS

Write to a range of bytes in memory.

.DESCRIPTION

Write-UCMemory writes to a range of bytes previously mapped in memory with the Initialize-UCMemoryMap function.

.PARAMETER Session

The Unicorn Engine emulator handle returned from New-UCEmulatorSession.

.PARAMETER Address

Specifies the starting memory address of bytes to set.

.PARAMETER Data

Specifies the bytes to be written to memory.

.EXAMPLE

PS C:\>$Session = New-UCEmulatorSession -X86 -X86Mode MODE_32
PS C:\>$Session | Initialize-UCMemoryMap -Address 0x1000000 -Size (2 * 4KB)
PS C:\>$Session | Write-UCMemory -Address 0x1000000 -Data @(0x90, 0x90, 0x90)
PS C:\>$Session | Read-UCMemory -Address 0x1000000 -Size 3

.INPUTS

PSObject

You can pipe a Unicorn Engine session handle returned from New-UCEmulatorSession to Read-UCMemory.

.OUTPUTS

System.Byte[]

Outputs a byte array consisting of the data read from memory.
#>

    [OutputType([Byte[]])]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [IntPtr]
        [ValidateScript({ $_ -and ($_ -ne [IntPtr]::Zero) })]
        $Session,

        [Parameter(Mandatory = $True)]
        [UInt64]
        $Address,

        [Parameter(Mandatory = $True)]
        [UInt32]
        [ValidateNotNullOrEmpty()]
        $Size
    )

    $Bytes = New-Object Byte[]($Size)

    $Status = [UnicornEngine.NativeMethods.unicorn]::uc_mem_read($Session, $Address, $Bytes, $Size)

    Assert-UCError -ErrorCode $Status -Context $MyInvocation

    return $Bytes
}

function Set-UCRegister {
<#
.SYNOPSIS

Writes a value to a register.

.DESCRIPTION

Set-UCRegister writes a value to the specified register.

.PARAMETER Session

The Unicorn Engine emulator handle returned from New-UCEmulatorSession.

.PARAMETER RegisterX86

Specifies the X86 register to write to.

.PARAMETER RegisterArm

Specifies the Arm register to write to.

.PARAMETER RegisterArm64

Specifies the Arm64 register to write to.

.PARAMETER RegisterM68K

Specifies the M68K register to write to.

.PARAMETER RegisterMips

Specifies the Mips register to write to.

.PARAMETER RegisterSparc

Specifies the Sparc register to write to.

.PARAMETER Value

Specifies the value to write to the specified register.

.PARAMETER PassThru

Indicates that the value of the specified register after it is set should be returned.

.EXAMPLE

PS C:\>$Session = New-UCEmulatorSession -X86 -X86Mode MODE_32
PS C:\>$Session | Set-UCRegister -RegisterX86 EAX -Value 0x1234

.EXAMPLE

PS C:\>$Session = New-UCEmulatorSession -X86 -X86Mode MODE_32
PS C:\>$SetValue = $Session | Set-UCRegister -RegisterX86 EAX -Value 0x1234 -PassThru

.INPUTS

PSObject

You can pipe a Unicorn Engine session handle returned from New-UCEmulatorSession to Set-UCRegister.

.OUTPUTS

None or System.Int64

If the -PassThru switch is specified, Set-UCRegister outputs the value of the specified register after it is set.
#>

    [OutputType([Int64])]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [IntPtr]
        [ValidateScript({ $_ -and ($_ -ne [IntPtr]::Zero) })]
        $Session,

        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'RegisterX86')]
        [UnicornEngine.Const.Reg.X86]
        $RegisterX86,

        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'RegisterArm')]
        [UnicornEngine.Const.Reg.Arm]
        $RegisterArm,

        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'RegisterArm64')]
        [UnicornEngine.Const.Reg.Arm64]
        $RegisterArm64,

        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'RegisterM68K')]
        [UnicornEngine.Const.Reg.M68K]
        $RegisterM68K,

        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'RegisterMips')]
        [UnicornEngine.Const.Reg.Mips]
        $RegisterMips,

        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'RegisterSparc')]
        [UnicornEngine.Const.Reg.Sparc]
        $RegisterSparc,

        [Parameter(Mandatory = $True, Position = 1)]
        [Int64]
        $Value,

        [Switch]
        $PassThru
    )

    switch ($PSCmdlet.ParameterSetName) {
        'RegisterX86' { $Register = $RegisterX86 }
        'RegisterArm' { $Register = $RegisterArm }
        'RegisterArm64' { $Register = $RegisterArm64 }
        'RegisterM68K' { $Register = $RegisterM68K }
        'RegisterMips' { $Register = $RegisterMips }
        'RegisterSparc' { $Register = $RegisterSparc }
    }

    $Status = [UnicornEngine.NativeMethods.unicorn]::uc_reg_write($Session, $Register, [Ref] $Value)

    Assert-UCError -ErrorCode $Status -Context $MyInvocation

    if ($PSBoundParameters['PassThru']) {
        $SetRegisterValue = $Session | Get-UCRegister $Register

        if ($SetRegisterValue -ne $Value) {
            throw "The register value was not set properly! Value provided: $Value. Returned value: $SetRegisterValue"
        }

        return $SetRegisterValue
    }
}

function Get-UCRegister {
<#
.SYNOPSIS

Reads a register value.

.DESCRIPTION

Get-UCRegister reads the value from a specified register.

.PARAMETER Session

The Unicorn Engine emulator handle returned from New-UCEmulatorSession.

.PARAMETER RegisterX86

Specifies the X86 register to read.

.PARAMETER RegisterArm

Specifies the Arm register to read.

.PARAMETER RegisterArm64

Specifies the Arm64 register to read.

.PARAMETER RegisterM68K

Specifies the M68K register to read.

.PARAMETER RegisterMips

Specifies the Mips register to read.

.PARAMETER RegisterSparc

Specifies the Sparc register to read.

.EXAMPLE

PS C:\>$Session = New-UCEmulatorSession -X86 -X86Mode MODE_32
PS C:\>$Session | Set-UCRegister -RegisterX86 EAX -Value 0x1234
PS C:\>$Session | Get-UCRegister -RegisterX86 EAX

.INPUTS

PSObject

You can pipe a Unicorn Engine session handle returned from New-UCEmulatorSession to Get-UCRegister.

.OUTPUTS

System.Int64

Outputs the value of the specified register.
#>

    [OutputType([Int64])]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [IntPtr]
        [ValidateScript({ $_ -and ($_ -ne [IntPtr]::Zero) })]
        $Session,

        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'RegisterX86')]
        [UnicornEngine.Const.Reg.X86]
        $RegisterX86,

        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'RegisterArm')]
        [UnicornEngine.Const.Reg.Arm]
        $RegisterArm,

        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'RegisterArm64')]
        [UnicornEngine.Const.Reg.Arm64]
        $RegisterArm64,

        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'RegisterM68K')]
        [UnicornEngine.Const.Reg.M68K]
        $RegisterM68K,

        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'RegisterMips')]
        [UnicornEngine.Const.Reg.Mips]
        $RegisterMips,

        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'RegisterSparc')]
        [UnicornEngine.Const.Reg.Sparc]
        $RegisterSparc
    )

    switch ($PSCmdlet.ParameterSetName) {
        'RegisterX86' { $Register = $RegisterX86 }
        'RegisterArm' { $Register = $RegisterArm }
        'RegisterArm64' { $Register = $RegisterArm64 }
        'RegisterM68K' { $Register = $RegisterM68K }
        'RegisterMips' { $Register = $RegisterMips }
        'RegisterSparc' { $Register = $RegisterSparc }
    }

    $Value = [Int64] 0

    $Status = [UnicornEngine.NativeMethods.unicorn]::uc_reg_read($Session, $Register, [Ref] $Value)

    Assert-UCError -ErrorCode $Status -Context $MyInvocation

    return $Value
}

filter Remove-UCEmulatorSession {
<#
.SYNOPSIS

Closes an open Unicorn Engine emulator session.

.DESCRIPTION

In order to prevent memory leaks, you should call Remove-UCEmulatorSession in order to properly close an established Unicorn Engine emulator session.

.PARAMETER Session

The Unicorn Engine emulator handle returned from New-UCEmulatorSession.

.EXAMPLE

PS C:\>$Session = New-UCEmulatorSession -X86 -X86Mode MODE_32
PS C:\>$Session | Remove-UCEmulatorSession

.INPUTS

PSObject

You can pipe a Unicorn Engine session handle returned from New-UCEmulatorSession to Remove-UCEmulatorSession.

.OUTPUTS

None

.NOTES

Remove-UCEmulatorSession zeroes out the argument passed in via -Session. This is to help ensure that a previous hook handle is not reused.
#>

    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [IntPtr]
        [ValidateScript({ $_ -and ($_ -ne [IntPtr]::Zero) })]
        $Session
    )

    $Status = [UnicornEngine.NativeMethods.unicorn]::uc_close($Session)

    # Invalidate the session handle so that it can no longer be used
    # Yes, I know I'm violating the rules of scope by doing this but it is
    # imperitive that the argument passed in the parent scope be set to zero.
    [IntPtr].GetField('m_value', [Reflection.BindingFlags] 'NonPublic, Instance').SetValue($Session, [IntPtr]::Zero)

    Assert-UCError -ErrorCode $Status -Context $MyInvocation
}

function Start-UCEmulatorSession {
<#
.SYNOPSIS

Emulate machine code in a specific duration of time.

.DESCRIPTION

Start-UCEmulatorSession

.PARAMETER Session

The Unicorn Engine emulator handle returned from New-UCEmulatorSession.

.PARAMETER StartAddress

Specifies the address where emulation starts.

.PARAMETER EndAddress

Specifies the address where emulation stops (i.e when this address is hit).

.PARAMETER Timeout

Specifies the duration to emulate the code (in microseconds). When this value is 0 (default), code is emulated indefinitely until execution completes.

.PARAMETER Count

Specifies the number of instructions to be emulated. When this value is 0 (default), all the code available is emulated until execution completes.

.EXAMPLE

PS C:\>$X86Code = @(0x41, 0x4A) # INC ecx; DEC edx
PS C:\>$Address = 0x1000000
PS C:\>$Session = New-UCEmulatorSession -X86 -X86Mode MODE_32
PS C:\>$Session | Initialize-UCMemoryMap -Address $Address -Size 2048KB
PS C:\>$Session | Write-UCMemory -Address $Address -Data $X86Code
PS C:\>$Session | Set-UCRegister -RegisterX86 ECX -Value 0x1234
PS C:\>$Session | Set-UCRegister -RegisterX86 EDX -Value 0x7890
PS C:\>$Session | Start-UCEmulatorSession -StartAddress $Address -EndAddress ($Address + $X86Code.Length)
PS C:\>$Session | Get-UCRegister -RegisterX86 ECX
PS C:\>$Session | Get-UCRegister -RegisterX86 EDX
PS C:\>$Session | Remove-UCEmulatorSession

.INPUTS

PSObject

You can pipe a Unicorn Engine session handle returned from New-UCEmulatorSession to Start-UCEmulatorSession.

.OUTPUTS

None
#>

    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [IntPtr]
        [ValidateScript({ $_ -and ($_ -ne [IntPtr]::Zero) })]
        $Session,

        [Parameter(Mandatory = $True)]
        [UInt64]
        $StartAddress,

        [Parameter(Mandatory = $True)]
        [UInt64]
        $EndAddress,

        [UInt64]
        $Timeout = 0,

        [UInt32]
        $Count = 0
    )

    $Status = [UnicornEngine.NativeMethods.unicorn]::uc_emu_start($Session, $StartAddress, $EndAddress, $Timeout, $Count)

    Assert-UCError -ErrorCode $Status -Context $MyInvocation
}

function Stop-UCEmulatorSession {
<#
.SYNOPSIS

Halts the emulator that was started with Start-UCEmulatorSession.

.DESCRIPTION

Stop-UCEmulatorSession halts the emulator that was started with Start-UCEmulatorSession. It is intended to only execute within a hook callback scriptblock.

.PARAMETER Session

The Unicorn Engine emulator handle returned from New-UCEmulatorSession.

.EXAMPLE

PS C:\>$X86Code = @(0x41) # INC ecx
PS C:\>$Address = 0x1000000
PS C:\>$CodeHook = {
    param (
        [IntPtr]
        $Session,

        [UInt64]
        $Address,

        [UInt32]
        $Size
    )

    $Session | Stop-UCEmulatorSession
}

PS C:\>$Session = New-UCEmulatorSession -X86 -X86Mode MODE_32
PS C:\>$Session | Initialize-UCMemoryMap -Address $Address -Size 2048KB
PS C:\>$Session | Write-UCMemory -Address $Address -Data $X86Code
PS C:\>$HookHandle = $Session | Register-UCHook -CodeHook -Action $CodeHook
PS C:\>$Session | Start-UCEmulatorSession -StartAddress $Address -EndAddress ($Address + $X86Code.Length)
PS C:\>$Session | Remove-UCEmulatorSession

.INPUTS

PSObject

You can pipe a Unicorn Engine session handle returned from New-UCEmulatorSession to Read-UCMemory.

.OUTPUTS

None
#>

    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [IntPtr]
        [ValidateScript({ $_ -and ($_ -ne [IntPtr]::Zero) })]
        $Session
    )

    $Status = [UnicornEngine.NativeMethods.unicorn]::uc_emu_stop($Session)

    Assert-UCError -ErrorCode $Status -Context $MyInvocation
}

function Register-UCHook {
<#
.SYNOPSIS

Register a scriptblock callback for a hook event.

.DESCRIPTION

Register-UCHook registers a user-provided scriptblock that will execute upon the firing of a hook event. Currently, Register-UCHook only supports code hooks.

Thank you to Oisin Grehan (@oising) for figuring out how to get scriptblock instrumentation callbacks working!!!

.PARAMETER Session

The Unicorn Engine emulator handle returned from New-UCEmulatorSession.

.PARAMETER Action

Specifies the scriptblock that will execute upon firing of an instrumentation hook.

.PARAMETER CodeHook

Specifies that a code hook is to be registered.

.PARAMETER InterruptHook

Specifies that an interrupt hook is to be registered.

.PARAMETER BasicBlockHook

Specifies that a basic block is to be registered.

.PARAMETER MemoryReadHook

Specifies that a memory read hook is to be registered.

.PARAMETER MemoryWriteHook

Specifies that a memory write hook is to be registered.

.PARAMETER InvalidMemAccessHook

Specifies that an invalid memory access hook is to be registered.

.PARAMETER SyscallHook

Specifies that a syscall hook is to be registered.

.PARAMETER X86InHook

Specifies that an x86 IN hook is to be registered.

.PARAMETER X86OutHook

Specifies that an x86 OUT hook is to be registered.

.PARAMETER BeginAddress

Trigger the callback at and above execution of instructions at this address.

.PARAMETER EndAddress

Trigger the callback at and below execution of instructions at this address.

.EXAMPLE

PS C:\>$X86Code = @(0x41, 0x4A) # INC ecx; DEC edx
PS C:\>$Address = 0x1000000

PS C:\>$CodeHook = {
    param (
        [IntPtr]
        $Session,

        [UInt64]
        $Address,

        [UInt32]
        $Size
    )

    Write-Host 'Operation: Instruction executed'
    Write-Host "Session handle: 0x$($Session.ToString('X16'))"
    Write-Host "Instruction address: 0x$($Address.ToString('X16')))"
    Write-Host "Instruction size: 0x$($Size.ToString('X8')))"
}

PS C:\>$Session = New-UCEmulatorSession -X86 -X86Mode MODE_32
PS C:\>$Session | Initialize-UCMemoryMap -Address $Address -Size 2048KB
PS C:\>$Session | Write-UCMemory -Address $Address -Data $X86Code
PS C:\>$CodeHookHandle = $Session | Register-UCHook -Action $CodeHook -CodeHook
PS C:\>$Session | Start-UCEmulatorSession -StartAddress $Address -EndAddress ($Address + $X86Code.Length)
PS C:\>$Session | Remove-UCEmulatorSession

Description
-----------
This will register and in theory, register a code hook. In practice, upon execution of the code hook, the scriptblock does not execute, access violates and crashed PowerShell.

.INPUTS

PSObject

You can pipe a Unicorn Engine session handle returned from New-UCEmulatorSession to Start-UCEmulatorSession.

.OUTPUTS

System.IntPtr

Outputs an IntPtr representing the registered hook handle. A hook may be unregister using the Remove-UCHook function.
#>

    [OutputType([IntPtr])]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [IntPtr]
        [ValidateScript({ $_ -and ($_ -ne [IntPtr]::Zero) })]
        $Session,

        [Parameter(Mandatory = $True, ParameterSetName = 'CodeHook')]
        [Switch]
        $CodeHook,

        [Parameter(Mandatory = $True, ParameterSetName = 'InterruptHook')]
        [Switch]
        $InterruptHook,

        [Parameter(Mandatory = $True, ParameterSetName = 'BlockHook')]
        [Switch]
        $BasicBlockHook,

        [Parameter(Mandatory = $True, ParameterSetName = 'ReadMemHook')]
        [Switch]
        $MemoryReadHook,

        [Parameter(Mandatory = $True, ParameterSetName = 'WriteMemHook')]
        [Switch]
        $MemoryWriteHook,

        [Parameter(Mandatory = $True, ParameterSetName = 'InvalidMemHook')]
        [Switch]
        $InvalidMemAccessHook,

        [Parameter(Mandatory = $True, ParameterSetName = 'SyscallHook')]
        [Switch]
        $SyscallHook,

        [Parameter(Mandatory = $True, ParameterSetName = 'InHook')]
        [Switch]
        $X86InHook,

        [Parameter(Mandatory = $True, ParameterSetName = 'OutHook')]
        [Switch]
        $X86OutHook,

        [Parameter(ParameterSetName = 'CodeHook')]
        [Parameter(ParameterSetName = 'BlockHook')]
        [Parameter(ParameterSetName = 'ReadMemHook')]
        [Parameter(ParameterSetName = 'WriteMemHook')]
        [UInt64]
        $BeginAddress = 1,

        [Parameter(ParameterSetName = 'CodeHook')]
        [Parameter(ParameterSetName = 'BlockHook')]
        [Parameter(ParameterSetName = 'ReadMemHook')]
        [Parameter(ParameterSetName = 'WriteMemHook')]
        [UInt64]
        $EndAddress = 0,

        [Parameter(Mandatory = $True)]
        [ScriptBlock]
        [ValidateNotNullOrEmpty()]
        $Action
    )

    $HookHandle = [IntPtr]::Zero

    switch ($PSCmdlet.ParameterSetName) {
        'CodeHook' {
            $Callback = New-UCHookCallback -Action $Action -CodeHook

            $Status = [UnicornEngine.NativeMethods.unicorn]::uc_hook_add_arg0_arg1($Session,
                                                                                   [Ref] $HookHandle,
                                                                                   [UnicornEngine.Const.uc_hook_type]::CODE,
                                                                                   $Callback,
                                                                                   [IntPtr]::Zero,
                                                                                   $BeginAddress,
                                                                                   $EndAddress)
        }

        'BlockHook' {
            $Callback = New-UCHookCallback -Action $Action -BasicBlockHook

            $Status = [UnicornEngine.NativeMethods.unicorn]::uc_hook_add_arg0_arg1($Session,
                                                                                   [Ref] $HookHandle,
                                                                                   [UnicornEngine.Const.uc_hook_type]::BLOCK,
                                                                                   $Callback,
                                                                                   [IntPtr]::Zero,
                                                                                   $BeginAddress,
                                                                                   $EndAddress)
        }

        'ReadMemHook' {
            $Callback = New-UCHookCallback -Action $Action -MemoryReadHook

            $Status = [UnicornEngine.NativeMethods.unicorn]::uc_hook_add_arg0_arg1($Session,
                                                                                   [Ref] $HookHandle,
                                                                                   [UnicornEngine.Const.uc_hook_type]::MEM_READ,
                                                                                   $Callback,
                                                                                   [IntPtr]::Zero,
                                                                                   $BeginAddress,
                                                                                   $EndAddress)
        }

        'WriteMemHook' {
            $Callback = New-UCHookCallback -Action $Action -MemoryWriteHook

            $Status = [UnicornEngine.NativeMethods.unicorn]::uc_hook_add_arg0_arg1($Session,
                                                                                   [Ref] $HookHandle,
                                                                                   [UnicornEngine.Const.uc_hook_type]::MEM_WRITE,
                                                                                   $Callback,
                                                                                   [IntPtr]::Zero,
                                                                                   $BeginAddress,
                                                                                   $EndAddress)
        }

        'InterruptHook' {
            $Callback = New-UCHookCallback -Action $Action -InterruptHook

            $Status = [UnicornEngine.NativeMethods.unicorn]::uc_hook_add_noargs($Session,
                                                                                [Ref] $HookHandle,
                                                                                [UnicornEngine.Const.uc_hook_type]::INTR,
                                                                                $Callback,
                                                                                [IntPtr]::Zero)
        }

        'InvalidMemHook' {
            $Callback = New-UCHookCallback -Action $Action -InvalidMemAccessHook

            # MEM_INVALID will be a catch-all until someone requests more granular invalid mem hook types
            $Status = [UnicornEngine.NativeMethods.unicorn]::uc_hook_add_noargs($Session,
                                                                                [Ref] $HookHandle,
                                                                                [UnicornEngine.Const.uc_hook_type]::MEM_INVALID,
                                                                                $Callback,
                                                                                [IntPtr]::Zero)
        }

        'InHook' {
            $Callback = New-UCHookCallback -Action $Action -X86InHook

            $Status = [UnicornEngine.NativeMethods.unicorn]::uc_hook_add_arg0($Session,
                                                                              [Ref] $HookHandle,
                                                                              [UnicornEngine.Const.uc_hook_type]::INSN,
                                                                              $Callback,
                                                                              [IntPtr]::Zero,
                                                                              [UnicornEngine.Const.Ins.X86]::IN)
        }

        'OutHook' {
            $Callback = New-UCHookCallback -Action $Action -X86OutHook

            $Status = [UnicornEngine.NativeMethods.unicorn]::uc_hook_add_arg0($Session,
                                                                              [Ref] $HookHandle,
                                                                              [UnicornEngine.Const.uc_hook_type]::INSN,
                                                                              $Callback,
                                                                              [IntPtr]::Zero,
                                                                              [UnicornEngine.Const.Ins.X86]::OUT)
        }

        'SyscallHook' {
            $Callback = New-UCHookCallback -Action $Action -SyscallHook

            $Status = [UnicornEngine.NativeMethods.unicorn]::uc_hook_add_arg0($Session,
                                                                              [Ref] $HookHandle,
                                                                              [UnicornEngine.Const.uc_hook_type]::INSN,
                                                                              $Callback,
                                                                              [IntPtr]::Zero,
                                                                              [UnicornEngine.Const.Ins.X86]::SYSCALL)
        }
    }

    Assert-UCError -ErrorCode $Status -Context $MyInvocation

    return $HookHandle
}

function Remove-UCHook {
<#
.SYNOPSIS

Removes a previously registered hook callback.

.DESCRIPTION

Remove-UCHook removes a previously registered hook callback that was registered with Register-UCHook.

.PARAMETER Session

The Unicorn Engine emulator handle returned from New-UCEmulatorSession.

.PARAMETER HookHandle

Specifies the hook handle returned from Register-UCHook.

.EXAMPLE

PS C:\>$X86Code = @(0x41) # INC ecx
PS C:\>$Address = 0x1000000
PS C:\>$Session = New-UCEmulatorSession -X86 -X86Mode MODE_32
PS C:\>$Session | Initialize-UCMemoryMap -Address $Address -Size 2048KB
PS C:\>$Session | Write-UCMemory -Address $Address -Data $X86Code
PS C:\>$Session | Start-UCEmulatorSession -StartAddress $Address -EndAddress ($Address + $X86Code.Length)
PS C:\>$HookHandle = $Session | Register-UCHook -CodeHook -Action { Write-Host 'Hook executed' }
PS C:\>$Session | Remove-UCHook -HookHandle $HookHandle

.INPUTS

PSObject

You can pipe a Unicorn Engine session handle returned from New-UCEmulatorSession to Read-UCMemory.

.OUTPUTS

None

.NOTES

Remove-UCHook zeroes out the argument passed in via -HookHandle. This is to help ensure that a previous hook handle is not reused.
#>

    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [IntPtr]
        [ValidateScript({ $_ -and ($_ -ne [IntPtr]::Zero) })]
        $Session,

        [Parameter(Mandatory = $True)]
        [IntPtr]
        [ValidateScript({ $_ -and ($_ -ne [IntPtr]::Zero) })]
        $HookHandle
    )

    $Status = [UnicornEngine.NativeMethods.unicorn]::uc_hook_del($Session, $HookHandle)

    # Yes, I know I'm violating the rules of scope by doing this but it is
    # imperitive that the argument passed in the parent scope be set to zero.
    [IntPtr].GetField('m_value', [Reflection.BindingFlags] 'NonPublic, Instance').SetValue($HookHandle, [IntPtr]::Zero)

    Assert-UCError -ErrorCode $Status -Context $MyInvocation
}

function New-UCHookTemplate {
<#
.SYNOPSIS

Outputs a scriptblock hook template for use with Register-UCHook.

.DESCRIPTION

New-UCHookTemplate should be used to output a scriptblock template for use with Register-UCHook. The scriptblock returned will contain named parameters matching the function signature of the corresponding hook. Because it may not be obvious to users how to properly interact with the Unicorn callback functions, New-UCHookTemplate will provide an intuitive template to work with.

.PARAMETER CodeHook

Specifies a code hook template.

.PARAMETER InterruptHook

Specifies an interrupt hook template.

.PARAMETER BasicBlockHook

Specifies a basic block template.

.PARAMETER MemoryReadHook

Specifies a memory read hook template.

.PARAMETER MemoryWriteHook

Specifies a memory write hook template.

.PARAMETER InvalidMemAccessHook

Specifies an invalid memory access hook template.

.PARAMETER SyscallHook

Specifies a syscall hook template.

.PARAMETER X86InHook

Specifies an x86 IN hook template.

.PARAMETER X86OutHook

Specifies an x86 OUT hook template.

.EXAMPLE

$CodeHookTemplate = New-UCHookTemplate -CodeHook

.INPUTS

None

.OUTPUTS

ScriptBlock

Outputs a scriptblock that corresponds to its respective Unicorn callback function.
#>

    [OutputType([ScriptBlock])]
    param (
        [Parameter(Mandatory = $True, ParameterSetName = 'CodeHook')]
        [Switch]
        $CodeHook,

        [Parameter(Mandatory = $True, ParameterSetName = 'InterruptHook')]
        [Switch]
        $InterruptHook,

        [Parameter(Mandatory = $True, ParameterSetName = 'BlockHook')]
        [Switch]
        $BasicBlockHook,

        [Parameter(Mandatory = $True, ParameterSetName = 'ReadMemHook')]
        [Switch]
        $MemoryReadHook,

        [Parameter(Mandatory = $True, ParameterSetName = 'WriteMemHook')]
        [Switch]
        $MemoryWriteHook,

        [Parameter(Mandatory = $True, ParameterSetName = 'InvalidMemHook')]
        [Switch]
        $InvalidMemAccessHook,

        [Parameter(Mandatory = $True, ParameterSetName = 'SyscallHook')]
        [Switch]
        $SyscallHook,

        [Parameter(Mandatory = $True, ParameterSetName = 'InHook')]
        [Switch]
        $X86InHook,

        [Parameter(Mandatory = $True, ParameterSetName = 'OutHook')]
        [Switch]
        $X86OutHook
    )

    $ScriptblockTemplate = {}

    switch ($PSCmdlet.ParameterSetName) {
        'CodeHook' {
            $ScriptblockTemplate = {
param (
    [IntPtr]
    $Session,

    [UInt64]
    $Address,

    [UInt32]
    $Size
)


}
        }

        'BlockHook' {
            $ScriptblockTemplate = {
param (
    [IntPtr]
    $Session,

    [UInt64]
    $Address,

    [UInt32]
    $Size
)


}
        }

        'InterruptHook' {
            $ScriptblockTemplate = {
param (
    [IntPtr]
    $Session,

    [UInt32]
    $InterruptNumber
)


}
        }

        'ReadMemHook' {
            $ScriptblockTemplate = {
param (
    [IntPtr]
    $Session,

    [UnicornEngine.Const.uc_mem]
    $Type,

    [UInt64]
    $Address,

    [UInt32]
    $Size,

    [Int64]
    $Value
)


}
        }

        'WriteMemHook' {
            $ScriptblockTemplate = {
param (
    [IntPtr]
    $Session,

    [UnicornEngine.Const.uc_mem]
    $Type,

    [UInt64]
    $Address,

    [UInt32]
    $Size,

    [Int64]
    $Value
)


}
        }

        'InvalidMemHook' {
            $ScriptblockTemplate = {
param (
    [IntPtr]
    $Session,

    [UnicornEngine.Const.uc_mem]
    $Type,

    [UInt64]
    $Address,

    [UInt32]
    $Size,

    [Int64]
    $Value
)


}
        }

        'InHook' {
            $ScriptblockTemplate = {
param (
    [IntPtr]
    $Session,

    [UInt32]
    $Port,

    [UInt32]
    $Size
)


}
        }

        'OutHook' {
            $ScriptblockTemplate = {
param (
    [IntPtr]
    $Session,

    [UInt32]
    $Port,

    [UInt32]
    $Size,

    [UInt32]
    $Value
)


}
        }

        'SyscallHook' {
            $ScriptblockTemplate = {
param (
    [IntPtr]
    $Session
)


}
        }
    }

    return $ScriptblockTemplate
}
#endregion