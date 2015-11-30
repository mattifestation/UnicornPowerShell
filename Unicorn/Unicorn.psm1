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
    (func unicorn uc_hook_add ($UC_ERR) @([IntPtr], [IntPtr].MakeByRefType(), $UC_HOOK, [MulticastDelegate], [IntPtr], [UInt64], [UInt64]))
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

function Assert-UCValidEmulatorSession {
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]
        [ValidateScript({ $_.PSObject.TypeNames[0] -eq 'UnicornEngine.EngineSession' })]
        $Session,

        [Management.Automation.InvocationInfo]
        $Context
    )

    $ContextMessage = ''

    if ($PSBoundParameters['Context']) {
        $ContextMessage = "$($Context.InvocationName): "
    }

    if ($PSBoundParameters['Session'].Open -eq $False) {
        throw "$($ContextMessage)Engine session was already closed."
    }

    if ($PSBoundParameters['Session'].EngineHandle -eq [IntPtr]::Zero) {
        throw "$($ContextMessage)Session engine handle is null. You cannot operate a session with a null handle."
    }

    if (-not [Enum]::IsDefined([UnicornEngine.Const.uc_arch], $PSBoundParameters['Session'].Arch)) {
        throw "$($ContextMessage)Invalid session architecture detected."
    }
}

function Get-DelegateType
{
    [OutputType([Type])]
    Param
    ( 
        [Parameter( Position = 0)]
        [Type[]]
        $Parameters = (New-Object Type[](0)),
            
        [Parameter( Position = 1 )]
        [Type]
        $ReturnType = [Void],

        [System.Runtime.InteropServices.CallingConvention]
        $CallingConvention
    )

    $Domain = [AppDomain]::CurrentDomain
    $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
    $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])

    if ($PSBoundParameters['CallingConvention']) {
        $CallingConventionConstructor = [Runtime.InteropServices.UnmanagedFunctionPointerAttribute].GetConstructor(@([Runtime.InteropServices.CallingConvention]))
        $ConstructorBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($CallingConventionConstructor, [Object[]] @($PSBoundParameters['CallingConvention']))
        $TypeBuilder.SetCustomAttribute($ConstructorBuilder)
    }

    $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
    $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
    $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
    $MethodBuilder.SetImplementationFlags('Runtime, Managed')
        
    Write-Output $TypeBuilder.CreateType()
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

Outputs a session object (Type name: "UnicornEngine.EngineSession") consisting of an emulator handle, handle status, and specified architecture.
#>

    [OutputType([PSObject])]
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

    $Properties = @{
        EngineHandle = $UCEngine
        Open = $True
        Arch = $Architecture
    }

    $EngineSession = New-Object -TypeName PSObject -Property $Properties
    $EngineSession.PSObject.TypeNames[0] = 'UnicornEngine.EngineSession'

    return $EngineSession
}

function Initialize-UCMemoryMap {
<#
.SYNOPSIS

Map memory in for emulation.

.DESCRIPTION

Initialize-UCMemoryMap maps in a memory page of a specific size and protection for use by the emulator.

.PARAMETER Session

The Unicorn Engine emulator session object returned from New-UCEmulatorSession.

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

You can pipe a Unicorn Engine session object returned from New-UCEmulatorSession to Initialize-UCMemoryMap.

.OUTPUTS

None
#>

    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]
        [ValidateScript({ $_.PSObject.TypeNames[0] -eq 'UnicornEngine.EngineSession' })]
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

    Assert-UCValidEmulatorSession -Session $Session -Context $MyInvocation

    $Status = [UnicornEngine.NativeMethods.unicorn]::uc_mem_map($Session.EngineHandle, $Address, $Size, $Protection)

    Assert-UCError -ErrorCode $Status -Context $MyInvocation
}

function Remove-UCMemoryMap {
<#
.SYNOPSIS

Unmap a region of emulation memory.

.DESCRIPTION

Remove-UCMemoryMap unmaps a previously mapped region of memory.

.PARAMETER Session

The Unicorn Engine emulator session object returned from New-UCEmulatorSession.

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

You can pipe a Unicorn Engine session object returned from New-UCEmulatorSession to Remove-UCMemoryMap.

.OUTPUTS

None
#>

    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]
        [ValidateScript({ $_.PSObject.TypeNames[0] -eq 'UnicornEngine.EngineSession' })]
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

    Assert-UCValidEmulatorSession -Session $Session -Context $MyInvocation

    $Status = [UnicornEngine.NativeMethods.unicorn]::uc_mem_unmap($Session.EngineHandle, $Address, $Size)

    Assert-UCError -ErrorCode $Status -Context $MyInvocation
}

function Set-UCMemoryProtection {
<#
.SYNOPSIS

Set memory permissions for emulation memory.

.DESCRIPTION

Set-UCMemoryProtection changes permissions on an existing memory region.

.PARAMETER Session

The Unicorn Engine emulator session object returned from New-UCEmulatorSession.

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

You can pipe a Unicorn Engine session object returned from New-UCEmulatorSession to Initialize-UCMemoryMap.

.OUTPUTS

None
#>

    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]
        [ValidateScript({ $_.PSObject.TypeNames[0] -eq 'UnicornEngine.EngineSession' })]
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

    Assert-UCValidEmulatorSession -Session $Session -Context $MyInvocation

    $Status = [UnicornEngine.NativeMethods.unicorn]::uc_mem_protect($Session.EngineHandle, $Address, $Size, $Protection)

    Assert-UCError -ErrorCode $Status -Context $MyInvocation
}

function Write-UCMemory {
<#
.SYNOPSIS

Write to a range of bytes in memory.

.DESCRIPTION

Write-UCMemory writes to a range of bytes previously mapped in memory with the Initialize-UCMemoryMap function.

.PARAMETER Session

The Unicorn Engine emulator session object returned from New-UCEmulatorSession.

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

You can pipe a Unicorn Engine session object returned from New-UCEmulatorSession to Write-UCMemory.

.OUTPUTS

None    
#>

    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]
        [ValidateScript({ $_.PSObject.TypeNames[0] -eq 'UnicornEngine.EngineSession' })]
        $Session,

        [Parameter(Mandatory = $True)]
        [UInt64]
        $Address,

        [Parameter(Mandatory = $True)]
        [Byte[]]
        [ValidateNotNullOrEmpty()]
        $Data
    )

    Assert-UCValidEmulatorSession -Session $Session -Context $MyInvocation

    $Status = [UnicornEngine.NativeMethods.unicorn]::uc_mem_write($Session.EngineHandle, $Address, $Data, $Data.Length)

    Assert-UCError -ErrorCode $Status -Context $MyInvocation
}

function Read-UCMemory {
<#
.SYNOPSIS

Write to a range of bytes in memory.

.DESCRIPTION

Write-UCMemory writes to a range of bytes previously mapped in memory with the Initialize-UCMemoryMap function.

.PARAMETER Session

The Unicorn Engine emulator session object returned from New-UCEmulatorSession.

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

You can pipe a Unicorn Engine session object returned from New-UCEmulatorSession to Read-UCMemory.

.OUTPUTS

System.Byte[]

Outputs a byte array consisting of the data read from memory.
#>

    [OutputType([Byte[]])]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]
        [ValidateScript({ $_.PSObject.TypeNames[0] -eq 'UnicornEngine.EngineSession' })]
        $Session,

        [Parameter(Mandatory = $True)]
        [UInt64]
        $Address,

        [Parameter(Mandatory = $True)]
        [UInt32]
        [ValidateNotNullOrEmpty()]
        $Size
    )

    Assert-UCValidEmulatorSession -Session $Session -Context $MyInvocation

    $Bytes = New-Object Byte[]($Size)

    $Status = [UnicornEngine.NativeMethods.unicorn]::uc_mem_read($Session.EngineHandle, $Address, $Bytes, $Size)

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

The Unicorn Engine emulator session object returned from New-UCEmulatorSession.

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

You can pipe a Unicorn Engine session object returned from New-UCEmulatorSession to Set-UCRegister.

.OUTPUTS

None or System.Int64

If the -PassThru switch is specified, Set-UCRegister outputs the value of the specified register after it is set.
#>

    [OutputType([Int64])]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]
        [ValidateScript({ $_.PSObject.TypeNames[0] -eq 'UnicornEngine.EngineSession' })]
        $Session,

        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'RegisterX86')]
        [UnicornEngine.Const.Reg.X86]
        [ValidateScript({ [Enum]::IsDefined($_.GetType(), $_) })]
        $RegisterX86,

        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'RegisterArm')]
        [UnicornEngine.Const.Reg.Arm]
        [ValidateScript({ [Enum]::IsDefined($_.GetType(), $_) })]
        $RegisterArm,

        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'RegisterArm64')]
        [UnicornEngine.Const.Reg.Arm64]
        [ValidateScript({ [Enum]::IsDefined($_.GetType(), $_) })]
        $RegisterArm64,

        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'RegisterM68K')]
        [UnicornEngine.Const.Reg.M68K]
        [ValidateScript({ [Enum]::IsDefined($_.GetType(), $_) })]
        $RegisterM68K,

        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'RegisterMips')]
        [UnicornEngine.Const.Reg.Mips]
        [ValidateScript({ [Enum]::IsDefined($_.GetType(), $_) })]
        $RegisterMips,

        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'RegisterSparc')]
        [UnicornEngine.Const.Reg.Sparc]
        [ValidateScript({ [Enum]::IsDefined($_.GetType(), $_) })]
        $RegisterSparc,

        [Parameter(Mandatory = $True, Position = 1)]
        [Int64]
        $Value,

        [Switch]
        $PassThru
    )

    Assert-UCValidEmulatorSession -Session $Session -Context $MyInvocation

    $ErrorMessage = "$($PSCmdlet.ParameterSetName.Substring('Register'.Length)) registers must match their respective architecture ($($Session.Arch))."

    switch ($PSCmdlet.ParameterSetName) {
        'RegisterX86' {
            if ($Session.Arch -ne 'ARCH_X86') { throw $ErrorMessage }
            $Register = $RegisterX86
        }

        'RegisterArm' {
            if ($Session.Arch -ne 'ARCH_ARM') { throw $ErrorMessage }
            $Register = $RegisterArm
        }

        'RegisterArm64' {
            if ($Session.Arch -ne 'ARCH_ARM64') { throw $ErrorMessage }
            $Register = $RegisterArm64
        }

        'RegisterM68K' {
            if ($Session.Arch -ne 'ARCH_M68K') { throw $ErrorMessage }
            $Register = $RegisterM68K
        }

        'RegisterMips' {
            if ($Session.Arch -ne 'ARCH_MIPS') { throw $ErrorMessage }
            $Register = $RegisterMips
        }

        'RegisterSparc' {
            if ($Session.Arch -ne 'ARCH_SPARC') { throw $ErrorMessage }
            $Register = $RegisterSparc
        }
    }

    $Status = [UnicornEngine.NativeMethods.unicorn]::uc_reg_write($Session.EngineHandle, $Register, [Ref] $Value)

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

The Unicorn Engine emulator session object returned from New-UCEmulatorSession.

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

You can pipe a Unicorn Engine session object returned from New-UCEmulatorSession to Get-UCRegister.

.OUTPUTS

System.Int64

Outputs the value of the specified register.
#>

    [OutputType([Int64])]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]
        [ValidateScript({ $_.PSObject.TypeNames[0] -eq 'UnicornEngine.EngineSession' })]
        $Session,

        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'RegisterX86')]
        [UnicornEngine.Const.Reg.X86]
        [ValidateScript({ [Enum]::IsDefined($_.GetType(), $_) })]
        $RegisterX86,

        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'RegisterArm')]
        [UnicornEngine.Const.Reg.Arm]
        [ValidateScript({ [Enum]::IsDefined($_.GetType(), $_) })]
        $RegisterArm,

        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'RegisterArm64')]
        [UnicornEngine.Const.Reg.Arm64]
        [ValidateScript({ [Enum]::IsDefined($_.GetType(), $_) })]
        $RegisterArm64,

        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'RegisterM68K')]
        [UnicornEngine.Const.Reg.M68K]
        [ValidateScript({ [Enum]::IsDefined($_.GetType(), $_) })]
        $RegisterM68K,

        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'RegisterMips')]
        [UnicornEngine.Const.Reg.Mips]
        [ValidateScript({ [Enum]::IsDefined($_.GetType(), $_) })]
        $RegisterMips,

        [Parameter(Mandatory = $True, Position = 0, ParameterSetName = 'RegisterSparc')]
        [UnicornEngine.Const.Reg.Sparc]
        [ValidateScript({ [Enum]::IsDefined($_.GetType(), $_) })]
        $RegisterSparc
    )

    Assert-UCValidEmulatorSession -Session $Session -Context $MyInvocation

    $ErrorMessage = "$($PSCmdlet.ParameterSetName.Substring('Register'.Length)) registers must match their respective architecture ($($Session.Arch))."

    switch ($PSCmdlet.ParameterSetName) {
        'RegisterX86' {
            if ($Session.Arch -ne 'ARCH_X86') { throw $ErrorMessage }
            $Register = $RegisterX86
        }

        'RegisterArm' {
            if ($Session.Arch -ne 'ARCH_ARM') { throw $ErrorMessage }
            $Register = $RegisterArm
        }

        'RegisterArm64' {
            if ($Session.Arch -ne 'ARCH_ARM64') { throw $ErrorMessage }
            $Register = $RegisterArm64
        }

        'RegisterM68K' {
            if ($Session.Arch -ne 'ARCH_M68K') { throw $ErrorMessage }
            $Register = $RegisterM68K
        }

        'RegisterMips' {
            if ($Session.Arch -ne 'ARCH_MIPS') { throw $ErrorMessage }
            $Register = $RegisterMips
        }

        'RegisterSparc' {
            if ($Session.Arch -ne 'ARCH_SPARC') { throw $ErrorMessage }
            $Register = $RegisterSparc
        }
    }

    $Value = [Int64] 0

    $Status = [UnicornEngine.NativeMethods.unicorn]::uc_reg_read($Session.EngineHandle, $Register, [Ref] $Value)

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

The Unicorn Engine emulator session object returned from New-UCEmulatorSession.

.EXAMPLE

PS C:\>$Session = New-UCEmulatorSession -X86 -X86Mode MODE_32
PS C:\>$Session | Remove-UCEmulatorSession

.INPUTS

PSObject

You can pipe a Unicorn Engine session object returned from New-UCEmulatorSession to Remove-UCEmulatorSession.

.OUTPUTS

None
#>

    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]
        [ValidateScript({ $_.PSObject.TypeNames[0] -eq 'UnicornEngine.EngineSession' })]
        $Session
    )

    Assert-UCValidEmulatorSession -Session $Session -Context $MyInvocation

    $Status = [UnicornEngine.NativeMethods.unicorn]::uc_close($Session.EngineHandle)

    # Invalidate the session object so that it can no longer be used
    $Session.Open = $False
    $Session.EngineHandle = [IntPtr]::Zero

    Assert-UCError -ErrorCode $Status -Context $MyInvocation
}

function Start-UCEmulatorSession {
<#
.SYNOPSIS

Emulate machine code in a specific duration of time.

.DESCRIPTION

Start-UCEmulatorSession

.PARAMETER Session

The Unicorn Engine emulator session object returned from New-UCEmulatorSession.

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

You can pipe a Unicorn Engine session object returned from New-UCEmulatorSession to Start-UCEmulatorSession.

.OUTPUTS

None
#>

    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]
        [ValidateScript({ $_.PSObject.TypeNames[0] -eq 'UnicornEngine.EngineSession' })]
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

    Assert-UCValidEmulatorSession -Session $Session -Context $MyInvocation

    $Status = [UnicornEngine.NativeMethods.unicorn]::uc_emu_start($Session.EngineHandle, $StartAddress, $EndAddress, $Timeout, $Count)

    Assert-UCError -ErrorCode $Status -Context $MyInvocation
}

function Register-UCHook {
<#
.SYNOPSIS

Register a scriptblock callback for a hook event.

.DESCRIPTION

Register-UCHook registers a user-provided scriptblock that will execute upon the firing of a hook event. Currently, Register-UCHook only supports code hooks.

HELP!!! Due to the thread that executes the hooks not having its own runspace, PowerShell scriptblocks will not execute in the context of the thread. The ability to execute scriptblocks in response to hook events is considered a core feature of the PowerShell Unicorn binding so if someone can figure out how to get this working, I would be eternally grateful!!! Thus far, I have tried the techniques explained in the following articles:
http://www.nivot.org/post/2009/10/09/PowerShell20AsynchronousCallbacksFromNET
http://www.exploit-monday.com/2013/06/PowerShellCallbackFunctions.html

The python implementation of callback registration can be found here: https://github.com/unicorn-engine/unicorn/blob/master/bindings/python/unicorn/unicorn.py#L301

.PARAMETER Session

The Unicorn Engine emulator session object returned from New-UCEmulatorSession.

.PARAMETER Action

Specifies the scriptblock that will execute upon firing of an instrumentation hook.

.EXAMPLE

PS C:\>$X86Code = @(0x41, 0x4A) # INC ecx; DEC edx
PS C:\>$Address = 0x1000000

PS C:\>$CodeHook = {
    param (
        [IntPtr]
        $SessionHandle,

        [UInt64]
        $Address,

        [UInt32]
        $Size,

        [IntPtr]
        $UserData
    )

    Write-Host "0x$($SessionHandle.ToString('X16'))"
    Write-Host "0x$($Address.ToString('X16')))"
    Write-Host "0x$($Size.ToString('X8')))"
    Write-Host "0x$($UserData.ToString('X16')))"
}

PS C:\>$Session = New-UCEmulatorSession -X86 -X86Mode MODE_32
PS C:\>$Session | Initialize-UCMemoryMap -Address $Address -Size 2048KB
PS C:\>$Session | Write-UCMemory -Address $Address -Data $X86Code
PS C:\>$Session | Set-UCRegister -RegisterX86 ECX -Value 0x1234
PS C:\>$Session | Set-UCRegister -RegisterX86 EDX -Value 0x7890
PS C:\>$Session | Register-UCHook -Action $CodeHook
PS C:\>$Session | Start-UCEmulatorSession -StartAddress $Address -EndAddress ($Address + $X86Code.Length)
PS C:\>$Session | Get-UCRegister -RegisterX86 ECX
PS C:\>$Session | Get-UCRegister -RegisterX86 EDX
PS C:\>$Session | Remove-UCEmulatorSession

Description
-----------
This will register and in theory, register a code hook. In practice, upon execution of the code hook, the scriptblock does not execute, throws the following error "There is no Runspace available to run scripts in this thread. You can provide one in the DefaultRunspace property of the System.Management.Automation.Runspaces.Runspace type. The script block you attempted to invoke was ...", and crashes PowerShell.

.INPUTS

PSObject

You can pipe a Unicorn Engine session object returned from New-UCEmulatorSession to Start-UCEmulatorSession.

.OUTPUTS

System.IntPtr

Outputs an IntPtr representing the registered hook handle.
#>

    [CmdletBinding()]
    [OutputType([IntPtr])]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSObject]
        [ValidateScript({ $_.PSObject.TypeNames[0] -eq 'UnicornEngine.EngineSession' })]
        $Session,

        [Parameter(Mandatory = $True)]
        [ScriptBlock]
        $Action
    )

    Assert-UCValidEmulatorSession -Session $Session -Context $MyInvocation

    $HookHandle = [IntPtr]::Zero

    $Delegate = Get-DelegateType -Parameters @([IntPtr], [UInt64], [UInt32], [IntPtr]) -ReturnType ([Int]) #-CallingConvention Cdecl

    $Callback = $Action -as $Delegate

    $ScriptBlockPtr = [Delegate].GetField('_methodPtr', [Reflection.BindingFlags] 'NonPublic, Instance').GetValue($Callback).ToString('X16')
    Write-Verbose "Scriptblock unmanaged addr: 0x$ScriptBlockPtr"

    # For the purposes of debugging, you should validate that the address at $ScriptBlockPtr and $Callback are executed

    # Todo: If this ever works, I would like to add a -Context parameter that would be passed to the scriptblock.

    $Status = [UnicornEngine.NativeMethods.unicorn]::uc_hook_add($Session.EngineHandle, [Ref] $HookHandle, [UnicornEngine.Const.uc_hook_type]::CODE, $Callback, [IntPtr]::Zero, 1, 0)

    Assert-UCError -ErrorCode $Status -Context $MyInvocation

    return $HookHandle
}
#endregion