Set-StrictMode -Version Latest

$TestScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
$ModuleRoot = Resolve-Path "$TestScriptRoot\.."
$ModuleManifest = "$ModuleRoot\Unicorn.psd1"

Remove-Module [U]nicorn
Import-Module $ModuleManifest -Force -ErrorAction Stop


Describe 'Module wide tests' {
    Context 'proper dependencies loaded' {
        It 'should have loaded a single unicorn.dll' {
            $SelfProc = Get-Process -Id $PID

            $UnicornModule = $SelfProc.Modules | Where-Object { $_.ModuleName -eq 'unicorn.dll' }

            $UnicornModule | Should Not BeNullOrEmpty
            $UnicornModule | Measure-Object | Select-Object -ExpandProperty Count | Should Be 1
        }
    }

    Context 'helper types loaded in memory' {
        It 'should have loaded the UnicornAssembly in-memory assembly' {
            $AssemblyFullName = 'UnicornAssembly, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null'

            $UnicornAssembly = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.FullName -eq $AssemblyFullName }

            $UnicornAssembly | Should Not BeNullOrEmpty
            $UnicornAssembly | Measure-Object | Select-Object -ExpandProperty Count | Should Be 1
        }

        It 'should have loaded all required in-memory types' {
            'UnicornEngine.NativeMethods.kernel32' -as [Type] | Should Not BeNullOrEmpty
            'UnicornEngine.NativeMethods.unicorn' -as [Type] | Should Not BeNullOrEmpty
            'UnicornEngine.Const.uc_arch' -as [Type] | Should Not BeNullOrEmpty
            'UnicornEngine.Const.uc_prot' -as [Type] | Should Not BeNullOrEmpty
            'UnicornEngine.Const.uc_err' -as [Type] | Should Not BeNullOrEmpty
            'UnicornEngine.Const.Mode.X86' -as [Type] | Should Not BeNullOrEmpty
            'UnicornEngine.Const.Mode.Arm' -as [Type] | Should Not BeNullOrEmpty
            'UnicornEngine.Const.Mode.Arm64' -as [Type] | Should Not BeNullOrEmpty
            'UnicornEngine.Const.Mode.Mips' -as [Type] | Should Not BeNullOrEmpty
            'UnicornEngine.Const.Mode.Sparc' -as [Type] | Should Not BeNullOrEmpty
            'UnicornEngine.Const.Ins.X86' -as [Type] | Should Not BeNullOrEmpty
            'UnicornEngine.Const.Reg.X86' -as [Type] | Should Not BeNullOrEmpty
            'UnicornEngine.Const.Reg.Arm' -as [Type] | Should Not BeNullOrEmpty
            'UnicornEngine.Const.Reg.Arm64' -as [Type] | Should Not BeNullOrEmpty
            'UnicornEngine.Const.Reg.M68K' -as [Type] | Should Not BeNullOrEmpty
            'UnicornEngine.Const.Reg.Mips' -as [Type] | Should Not BeNullOrEmpty
            'UnicornEngine.Const.Reg.Sparc' -as [Type] | Should Not BeNullOrEmpty
            'UnicornEngine.Const.uc_hook_type' -as [Type] | Should Not BeNullOrEmpty
            'UnicornEngine.Const.uc_mem' -as [Type] | Should Not BeNullOrEmpty
        }
    }
}

Describe 'Get-UCVersion' {
    Context 'return value validation' {
        It 'should return a System.Version object' {
            (Get-UCVersion) -is [Version] | Should Be $True
        }

        It 'should not return a zeroed out version number' {
            $NullVersion = New-Object Version(0,0,0,0)

            (Get-UCVersion) -eq $NullVersion | Should Be $False
        }

        It 'should be version 0.9 of the Unicorn engine' {
            $CorrectVersion = New-Object Version(0,9,0,0)

            (Get-UCVersion) -eq $CorrectVersion | Should Be $True
        }
    }
}

Describe 'New-UCEmulatorSession' {
    Context 'parameter validation' {
        It 'should accept expected X86 options' {
            $Session = New-UCEmulatorSession -X86 -X86Mode MODE_16
            $Session | Should Not BeNullOrEmpty
            $Session | Remove-UCEmulatorSession

            $Session = New-UCEmulatorSession -X86 -X86Mode MODE_32
            $Session | Should Not BeNullOrEmpty
            $Session | Remove-UCEmulatorSession

            $Session = New-UCEmulatorSession -X86 -X86Mode MODE_64
            $Session | Should Not BeNullOrEmpty
            $Session | Remove-UCEmulatorSession
        }

        It 'should accept expected Arm options' {
            $Session = New-UCEmulatorSession -Arm -ArmMode MODE_ARM
            $Session | Should Not BeNullOrEmpty
            $Session | Remove-UCEmulatorSession

            $Session = New-UCEmulatorSession -Arm -ArmMode MODE_THUMB
            $Session | Should Not BeNullOrEmpty
            $Session | Remove-UCEmulatorSession
        }

        It 'should accept expected Arm64 options' {
            $Session = New-UCEmulatorSession -Arm64 -Arm64Mode MODE_ARM
            $Session | Should Not BeNullOrEmpty
            $Session | Remove-UCEmulatorSession

            $Session = New-UCEmulatorSession -Arm64 -Arm64Mode MODE_V8
            $Session | Should Not BeNullOrEmpty
            $Session | Remove-UCEmulatorSession

            $Session = New-UCEmulatorSession -Arm64 -Arm64Mode MODE_MCLASS
            $Session | Should Not BeNullOrEmpty
            $Session | Remove-UCEmulatorSession
        }

        It 'should accept expected M68K options' {
            $Session = New-UCEmulatorSession -M68K
            $Session | Should Not BeNullOrEmpty
            $Session | Remove-UCEmulatorSession
        }

        It 'should accept expected Sparc options' {
            $Session = New-UCEmulatorSession -Sparc -SparcMode MODE_32
            $Session | Should Not BeNullOrEmpty
            $Session | Remove-UCEmulatorSession

            $Session = New-UCEmulatorSession -Sparc -SparcMode MODE_V9
            $Session | Should Not BeNullOrEmpty
            $Session | Remove-UCEmulatorSession
        }

        It 'should accept expected Mips options' {
            $Session = New-UCEmulatorSession -Mips -MipsMode MODE_MIPS32
            $Session | Should Not BeNullOrEmpty
            $Session | Remove-UCEmulatorSession

            $Session = New-UCEmulatorSession -Mips -MipsMode MODE_MIPS64
            $Session | Should Not BeNullOrEmpty
            $Session | Remove-UCEmulatorSession

            $Session = New-UCEmulatorSession -Mips -MipsMode MODE_MIPS32BE
            $Session | Should Not BeNullOrEmpty
            $Session | Remove-UCEmulatorSession

            $Session = New-UCEmulatorSession -Mips -MipsMode MODE_MIPS64BE
            $Session | Should Not BeNullOrEmpty
            $Session | Remove-UCEmulatorSession
        }
    }
}

Describe 'Remove-UCEmulatorSession' {
    Context 'parameter validation' {
        It 'should accept a valid single session over the pipeline' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            { $ValidSession | Remove-UCEmulatorSession } | Should Not Throw
        }

        It 'should accept a multiple valid sessions over the pipeline' {
            $ValidSession1 = New-UCEmulatorSession -X86 -X86Mode MODE_32
            $ValidSession2 = New-UCEmulatorSession -X86 -X86Mode MODE_64

            $SessionArray = @($ValidSession1, $ValidSession2)

            { $SessionArray | Remove-UCEmulatorSession } | Should Not Throw
        }

        It 'should accept a valid session argument passed as the -Session parameter' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            { Remove-UCEmulatorSession -Session $ValidSession } | Should Not Throw
        }

        It 'should not accept an non-session object' {
            { Remove-UCEmulatorSession -Session 'foo' } | Should Throw
        }

        It 'should not accept a null engine handle' {
            $NullSession = [IntPtr]::Zero

            { Remove-UCEmulatorSession -Session $NullSession } | Should Throw
        }
    }
}

Describe 'Initialize-UCMemoryMap' {
    Context 'parameter validation' {
        $InvalidSession = [IntPtr]::Zero

        $ValidAddress = 0x1000000
        $ValidSize = 2 * 4KB
        $ValidProtection = [UnicornEngine.Const.uc_prot]::ALL
        $InvalidAddress = 0x1000001
        $InvalidSize = (2 * 4KB) + 1

        It 'should accept a valid session over the pipeline' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            { $ValidSession | Initialize-UCMemoryMap -Address $ValidAddress -Size $ValidSize -Protection $ValidProtection } | Should Not Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }

        It 'should accept a valid session argument passed as the -Session parameter' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            { Initialize-UCMemoryMap -Session $ValidSession -Address $ValidAddress -Size $ValidSize -Protection $ValidProtection } | Should Not Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }

        It 'should not accept an invalid session' {
            { Initialize-UCMemoryMap -Session $InvalidSession -Address $ValidAddress -Size $ValidSize -Protection $ValidProtection } | Should Throw
        }

        It 'should not accept a non 4KB (0x1000) aligned address' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            { Initialize-UCMemoryMap -Session $ValidSession -Address $InvalidAddress -Size $ValidSize -Protection $ValidProtection } | Should Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }

        It 'should not accept a non 4KB (0x1000) aligned size' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            { Initialize-UCMemoryMap -Session $ValidSession -Address $ValidAddress -Size $InvalidSize -Protection $ValidProtection } | Should Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }
    }
}

Describe 'Set-UCMemoryProtection' {
    $InvalidSession = [IntPtr]::Zero

    $ValidAddress = 0x1000000
    $ValidSize = 2 * 4KB
    $ValidProtection = [UnicornEngine.Const.uc_prot]::ALL
    $InvalidAddress = 0x1000001
    $InvalidSize = (2 * 4KB) + 1

    Context 'parameter validation' {
        It 'should accept a valid session over the pipeline' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            $ValidSession | Initialize-UCMemoryMap -Address $ValidAddress -Size $ValidSize -Protection $ValidProtection
            
            { $ValidSession | Set-UCMemoryProtection -Address $ValidAddress -Size $ValidSize -Protection READ } | Should Not Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }

        It 'should accept a valid session argument passed as the -Session parameter' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            Initialize-UCMemoryMap -Session $ValidSession -Address $ValidAddress -Size $ValidSize -Protection $ValidProtection

            { Set-UCMemoryProtection -Session $ValidSession -Address $ValidAddress -Size $ValidSize -Protection READ } | Should Not Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }

        It 'should not accept an invalid session' {
            { Set-UCMemoryProtection -Session $InvalidSession -Address $ValidAddress -Size $ValidSize -Protection READ } | Should Throw
        }

        It 'should not accept a non 4KB (0x1000) aligned address' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            Initialize-UCMemoryMap -Session $ValidSession -Address $ValidAddress -Size $ValidSize -Protection $ValidProtection

            { Set-UCMemoryProtection -Session $ValidSession -Address $InvalidAddress -Size $ValidSize -Protection READ } | Should Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }

        It 'should not accept a non 4KB (0x1000) aligned size' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            Initialize-UCMemoryMap -Session $ValidSession -Address $ValidAddress -Size $ValidSize -Protection $ValidProtection

            { Set-UCMemoryProtection -Session $ValidSession -Address $ValidAddress -Size $InvalidSize -Protection READ } | Should Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }
    }

    Context 'intended behavior' {
        It 'should not change the protections on previously unmapped memory' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            Initialize-UCMemoryMap -Session $ValidSession -Address $ValidAddress -Size $ValidSize -Protection $ValidProtection
            Remove-UCMemoryMap -Session $ValidSession -Address $ValidAddress -Size $ValidSize

            { Set-UCMemoryProtection -Session $ValidSession -Address $ValidAddress -Size READ } | Should Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }

        It 'should not change the protections on memory that was never mapped' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            { Set-UCMemoryProtection -Session $ValidSession -Address $ValidAddress -Size READ } | Should Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }
    }
}

Describe 'Remove-UCMemoryMap' {
    $InvalidSession = [IntPtr]::Zero

    $ValidAddress = 0x1000000
    $ValidSize = 2 * 4KB
    $ValidProtection = [UnicornEngine.Const.uc_prot]::ALL
    $InvalidAddress = 0x1000001
    $InvalidSize = (2 * 4KB) + 1
    $InvalidProtection = [Enum]::Parse([UnicornEngine.Const.uc_prot], 1234)

    Context 'parameter validation' {
        It 'should accept a valid session over the pipeline' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            $ValidSession | Initialize-UCMemoryMap -Address $ValidAddress -Size $ValidSize -Protection $ValidProtection

            { $ValidSession | Remove-UCMemoryMap -Address $ValidAddress -Size $ValidSize } | Should Not Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }

        It 'should accept a valid session argument passed as the -Session parameter' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            Initialize-UCMemoryMap -Session $ValidSession -Address $ValidAddress -Size $ValidSize -Protection $ValidProtection

            { Remove-UCMemoryMap -Session $ValidSession -Address $ValidAddress -Size $ValidSize } | Should Not Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }

        It 'should not accept an invalid session' {
            { Remove-UCMemoryMap -Session $InvalidSession -Address $ValidAddress -Size $ValidSize } | Should Throw
        }

        It 'should not accept a non 4KB (0x1000) aligned address' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            Initialize-UCMemoryMap -Session $ValidSession -Address $ValidAddress -Size $ValidSize -Protection $ValidProtection

            { Remove-UCMemoryMap -Session $ValidSession -Address $InvalidAddress -Size $ValidSize } | Should Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }

        It 'should not accept a non 4KB (0x1000) aligned size' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            Initialize-UCMemoryMap -Session $ValidSession -Address $ValidAddress -Size $ValidSize -Protection $ValidProtection

            { Remove-UCMemoryMap -Session $ValidSession -Address $InvalidAddress -Size $InvalidSize } | Should Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }
    }

    Context 'intended behavior' {
        It 'should not unmap previously unmapped memory' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            Initialize-UCMemoryMap -Session $ValidSession -Address $ValidAddress -Size $ValidSize -Protection $ValidProtection

            { Remove-UCMemoryMap -Session $ValidSession -Address $ValidAddress -Size $ValidSize } | Should Not Throw
            { Remove-UCMemoryMap -Session $ValidSession -Address $ValidAddress -Size $ValidSize } | Should Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }

        It 'should not unmap memory that was never mapped' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            { Remove-UCMemoryMap -Session $ValidSession -Address $ValidAddress -Size $ValidSize } | Should Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }
    }
}

Describe 'Write-UCMemory' {
    $InvalidSession = [IntPtr]::Zero

    $MappedAddress = 0x1000000
    $ValidSize = 4KB
    $ValidProtection = [UnicornEngine.Const.uc_prot]::ALL
    $UnmappedAddress = 0
    $Nops = [Byte[]] @(0x90, 0x90, 0x90)
    $TooManyNops = [Byte[]] @(0x90) * (2 * $ValidSize)
    $InvalidProtection = [Enum]::Parse([UnicornEngine.Const.uc_prot], 1234)

    Context 'parameter validation' {
        It 'should accept a valid session over the pipeline' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            $ValidSession | Initialize-UCMemoryMap -Address $MappedAddress -Size $ValidSize -Protection $ValidProtection

            { $ValidSession | Write-UCMemory -Address $MappedAddress -Data $Nops } | Should Not Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }

        It 'should accept a valid session argument passed as the -Session parameter' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            $ValidSession | Initialize-UCMemoryMap -Address $MappedAddress -Size $ValidSize -Protection $ValidProtection

            { Write-UCMemory -Session $ValidSession -Address $MappedAddress -Data $Nops } | Should Not Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }

        It 'should not accept an invalid session' {
            { Write-UCMemory -Session $InvalidSession -Address $MappedAddress -Data $Nops } | Should Throw
        }

        It 'should not accept null data' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            $ValidSession | Initialize-UCMemoryMap -Address $MappedAddress -Size $ValidSize -Protection $ValidProtection

            { Write-UCMemory -Session $ValidSession -Address $MappedAddress -Data @() } | Should Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }
    }

    Context 'intended behavior' {
        It 'should not write to unmapped memory' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            { Write-UCMemory -Session $ValidSession -Address $MappedAddress -Data $Nops } | Should Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }

        It 'should not write data larger than the size of the mapped region' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            $ValidSession | Initialize-UCMemoryMap -Address $MappedAddress -Size $ValidSize -Protection $ValidProtection

            { Write-UCMemory -Session $ValidSession -Address $MappedAddress -Data $TooManyNops } | Should Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }

        It 'should not write to read-only memory' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            $ValidSession | Initialize-UCMemoryMap -Address $MappedAddress -Size $ValidSize -Protection ([UnicornEngine.Const.uc_prot]::READ)

            { Write-UCMemory -Session $ValidSession -Address $MappedAddress -Data $Nops } | Should Not Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }
    }
}

Describe 'Read-UCMemory' {
    $MappedAddress = 0x1000000
    $ValidSize = 4KB
    $ValidProtection = [UnicornEngine.Const.uc_prot]::ALL
    $WriteOnly = [UnicornEngine.Const.uc_prot]::WRITE
    $UnmappedAddress = 0
    $Nops = [Byte[]] @(0x90, 0x90, 0x90)

    Context 'parameter validation' {
        It 'should accept a valid session over the pipeline' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            $ValidSession | Initialize-UCMemoryMap -Address $MappedAddress -Size $ValidSize -Protection $ValidProtection

            $ValidSession | Write-UCMemory -Address $MappedAddress -Data $Nops

            { $ValidSession | Read-UCMemory -Address $MappedAddress -Size $Nops.Length } | Should Not Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }

        It 'should accept a valid session argument passed as the -Session parameter' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            $ValidSession | Initialize-UCMemoryMap -Address $MappedAddress -Size $ValidSize -Protection $ValidProtection

            $ValidSession | Write-UCMemory -Address $MappedAddress -Data $Nops

            { Read-UCMemory -Session $ValidSession -Address $MappedAddress -Size $Nops.Length } | Should Not Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }

        It 'should not accept an invalid session' {
            { Read-UCMemory -Session $InvalidSession -Address $MappedAddress -Size $Nops.Length } | Should Throw
        }

        It 'should not accept a negative size' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            $ValidSession | Initialize-UCMemoryMap -Address $MappedAddress -Size $ValidSize -Protection $ValidProtection

            { Read-UCMemory -Session $ValidSession -Address $MappedAddress -Size -1 } | Should Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }
    }

    Context 'return value validation' {
        It 'should return the same data that was written' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            $ValidSession | Initialize-UCMemoryMap -Address $MappedAddress -Size $ValidSize -Protection $ValidProtection

            $ValidSession | Write-UCMemory -Address $MappedAddress -Data $Nops

            $Data = Read-UCMemory -Session $ValidSession -Address $MappedAddress -Size $Nops.Length

            $Data[0] -eq $Nops[0] | Should Be $True
            $Data[1] -eq $Nops[1] | Should Be $True
            $Data[2] -eq $Nops[2] | Should Be $True

            Remove-UCEmulatorSession -Session $ValidSession
        }
    }

    Context 'intended behavior' {
        It 'should not read beyond the bounds of what was mapped' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            $ValidSession | Initialize-UCMemoryMap -Address $MappedAddress -Size $ValidSize -Protection $ValidProtection

            $ValidSession | Write-UCMemory -Address $MappedAddress -Data $Nops

            { Read-UCMemory -Session $ValidSession -Address $MappedAddress -Size ($ValidSize+1) } | Should Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }

        It 'should not read from unmapped memory' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            { Read-UCMemory -Session $ValidSession -Address 0 -Size 1 } | Should Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }
    }
}

Describe 'Get-UCRegister' {
    $InvalidSession = [IntPtr]::Zero

    $MappedAddress = 0x1000000
    $ValidSize = 4KB
    $ValidProtection = [UnicornEngine.Const.uc_prot]::ALL

    $Value = 0x1234

    $X86Register = [UnicornEngine.Const.Reg.X86]::EAX
    $ArmRegister = [UnicornEngine.Const.Reg.Arm]::R0
    $Arm64Register = [UnicornEngine.Const.Reg.Arm64]::X11
    $M68KRegister = [UnicornEngine.Const.Reg.M68K]::A0
    $MipsRegister = [UnicornEngine.Const.Reg.Mips]::REG_0
    $SparcRegister = [UnicornEngine.Const.Reg.Sparc]::G1

    Context 'parameter validation' {
        It 'should accept a valid session over the pipeline' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            $ValidSession | Initialize-UCMemoryMap -Address $MappedAddress -Size $ValidSize -Protection $ValidProtection

            { $ValidSession | Get-UCRegister -RegisterX86 $X86Register } | Should Not Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }

        It 'should accept a valid session argument passed as the -Session parameter' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            $ValidSession | Initialize-UCMemoryMap -Address $MappedAddress -Size $ValidSize -Protection $ValidProtection

            { Get-UCRegister -Session $ValidSession -RegisterX86 $X86Register } | Should Not Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }

        It 'should not accept an invalid session' {
            { Get-UCRegister -Session $InvalidSession -RegisterX86 $X86Register } | Should Throw
        }

        It 'should accept a valid X86 register' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            $ValidSession | Initialize-UCMemoryMap -Address $MappedAddress -Size $ValidSize -Protection $ValidProtection

            { Get-UCRegister -Session $ValidSession -RegisterX86 $X86Register } | Should Not Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }

        It 'should accept a valid Arm register' {
            $ValidSession = New-UCEmulatorSession -Arm -ArmMode MODE_ARM

            $ValidSession | Initialize-UCMemoryMap -Address $MappedAddress -Size $ValidSize -Protection $ValidProtection

            { Get-UCRegister -Session $ValidSession -RegisterArm $ArmRegister } | Should Not Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }

        It 'should accept a valid Arm64 register' {
            $ValidSession = New-UCEmulatorSession -Arm64 -Arm64Mode MODE_ARM

            $ValidSession | Initialize-UCMemoryMap -Address $MappedAddress -Size $ValidSize -Protection $ValidProtection

            { Get-UCRegister -Session $ValidSession -RegisterArm64 $Arm64Register } | Should Not Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }

        It 'should accept a valid M68K register' {
            $ValidSession = New-UCEmulatorSession -M68K

            $ValidSession | Initialize-UCMemoryMap -Address $MappedAddress -Size $ValidSize -Protection $ValidProtection

            { Get-UCRegister -Session $ValidSession -RegisterM68K $M68KRegister } | Should Not Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }

        It 'should accept a valid Mips register' {
            $ValidSession = New-UCEmulatorSession -Mips -MipsMode MODE_MIPS32

            $ValidSession | Initialize-UCMemoryMap -Address $MappedAddress -Size $ValidSize -Protection $ValidProtection

            { Get-UCRegister -Session $ValidSession -RegisterMips $MipsRegister } | Should Not Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }

        It 'should accept a valid Sparc register' {
            $ValidSession = New-UCEmulatorSession -Sparc -SparcMode MODE_32

            $ValidSession | Initialize-UCMemoryMap -Address $MappedAddress -Size $ValidSize -Protection $ValidProtection

            { Get-UCRegister -Session $ValidSession -RegisterSparc $SparcRegister } | Should Not Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }
    }

    Context 'intended behavior' {
        It 'should return the same register that was set earlier' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            $ValidSession | Initialize-UCMemoryMap -Address $MappedAddress -Size $ValidSize -Protection $ValidProtection

            Set-UCRegister -Session $ValidSession -RegisterX86 $X86Register -Value $Value

            $SetRegisterValue = Get-UCRegister -Session $ValidSession -RegisterX86 $X86Register

            $SetRegisterValue -eq $Value | Should Be $True

            Remove-UCEmulatorSession -Session $ValidSession
        }
    }
}

Describe 'Set-UCRegister' {
    $InvalidSession = [IntPtr]::Zero

    $MappedAddress = 0x1000000
    $ValidSize = 4KB
    $ValidProtection = [UnicornEngine.Const.uc_prot]::ALL

    $X86Register = [UnicornEngine.Const.Reg.X86]::EAX
    $ArmRegister = [UnicornEngine.Const.Reg.Arm]::R0
    $Arm64Register = [UnicornEngine.Const.Reg.Arm64]::X11
    $M68KRegister = [UnicornEngine.Const.Reg.M68K]::A0
    $MipsRegister = [UnicornEngine.Const.Reg.Mips]::REG_0
    $SparcRegister = [UnicornEngine.Const.Reg.Sparc]::G1

    $Value = 0x1000

    Context 'parameter validation' {
        It 'should accept a valid session over the pipeline' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            $ValidSession | Initialize-UCMemoryMap -Address $MappedAddress -Size $ValidSize -Protection $ValidProtection

            { $ValidSession | Set-UCRegister -RegisterX86 $X86Register -Value $Value -PassThru } | Should Not Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }

        It 'should accept a valid session argument passed as the -Session parameter' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            $ValidSession | Initialize-UCMemoryMap -Address $MappedAddress -Size $ValidSize -Protection $ValidProtection

            { Set-UCRegister -Session $ValidSession -RegisterX86 $X86Register -Value $Value -PassThru } | Should Not Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }

        It 'should not accept an invalid session' {
            { Set-UCRegister -Session $InvalidSession -RegisterX86 $X86Register -Value $Value } | Should Throw
        }

        It 'should accept a valid X86 register' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            $ValidSession | Initialize-UCMemoryMap -Address $MappedAddress -Size $ValidSize -Protection $ValidProtection

            { Set-UCRegister -Session $ValidSession -RegisterX86 $X86Register -Value $Value -PassThru } | Should Not Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }

        It 'should accept a valid Arm register' {
            $ValidSession = New-UCEmulatorSession -Arm -ArmMode MODE_ARM

            $ValidSession | Initialize-UCMemoryMap -Address $MappedAddress -Size $ValidSize -Protection $ValidProtection

            { Set-UCRegister -Session $ValidSession -RegisterArm $ArmRegister -Value $Value -PassThru } | Should Not Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }

        It 'should accept a valid Arm64 register' {
            $ValidSession = New-UCEmulatorSession -Arm64 -Arm64Mode MODE_ARM

            $ValidSession | Initialize-UCMemoryMap -Address $MappedAddress -Size $ValidSize -Protection $ValidProtection

            { Set-UCRegister -Session $ValidSession -RegisterArm64 $Arm64Register -Value $Value -PassThru } | Should Not Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }

        It 'should accept a valid M68K register' {
            $ValidSession = New-UCEmulatorSession -M68K

            $ValidSession | Initialize-UCMemoryMap -Address $MappedAddress -Size $ValidSize -Protection $ValidProtection

            { Set-UCRegister -Session $ValidSession -RegisterM68K $M68KRegister -Value $Value -PassThru } | Should Not Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }

        It 'should accept a valid Mips register' {
            $ValidSession = New-UCEmulatorSession -Mips -MipsMode MODE_MIPS32

            $ValidSession | Initialize-UCMemoryMap -Address $MappedAddress -Size $ValidSize -Protection $ValidProtection

            { Set-UCRegister -Session $ValidSession -RegisterMips $MipsRegister -Value $Value -PassThru } | Should Not Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }

        It 'should accept a valid Sparc register' {
            $ValidSession = New-UCEmulatorSession -Sparc -SparcMode MODE_32

            $ValidSession | Initialize-UCMemoryMap -Address $MappedAddress -Size $ValidSize -Protection $ValidProtection

            { Set-UCRegister -Session $ValidSession -RegisterSparc $SparcRegister -Value $Value -PassThru } | Should Not Throw

            Remove-UCEmulatorSession -Session $ValidSession
        }
    }

    Context 'intended behavior' {
        It 'should have set the register with the provided value' {
            $ValidSession = New-UCEmulatorSession -X86 -X86Mode MODE_32

            $ValidSession | Initialize-UCMemoryMap -Address $MappedAddress -Size $ValidSize -Protection $ValidProtection

            $SetRegisterValue = Set-UCRegister -Session $ValidSession -RegisterX86 $X86Register -Value $Value -PassThru

            $SetRegisterValue -eq $Value | Should Be $True

            Remove-UCEmulatorSession -Session $ValidSession
        }
    }
}

Describe 'Start-UCEmulatorSession' {
    $InvalidSession = [IntPtr]::Zero

    $X86Code = @(0x41, 0x4A) # INC ecx; DEC edx
    $Address = 0x1000000

    Context 'parameter validation' {
        It 'should accept a valid session over the pipeline' {
            $Session = New-UCEmulatorSession -X86 -X86Mode MODE_32
            $Session | Initialize-UCMemoryMap -Address $Address -Size 2048KB
            $Session | Write-UCMemory -Address $Address -Data $X86Code
            $Session | Set-UCRegister -RegisterX86 ECX -Value 0x1234
            $Session | Set-UCRegister -RegisterX86 EDX -Value 0x7890
            { $Session | Start-UCEmulatorSession -StartAddress $Address -EndAddress ($Address + $X86Code.Length) } | Should Not Throw
            $Session | Remove-UCEmulatorSession
        }

        It 'should accept a valid session argument passed as the -Session parameter' {
            $Session = New-UCEmulatorSession -X86 -X86Mode MODE_32
            $Session | Initialize-UCMemoryMap -Address $Address -Size 2048KB
            $Session | Write-UCMemory -Address $Address -Data $X86Code
            $Session | Set-UCRegister -RegisterX86 ECX -Value 0x1234
            $Session | Set-UCRegister -RegisterX86 EDX -Value 0x7890
            { Start-UCEmulatorSession -Session $Session -StartAddress $Address -EndAddress ($Address + $X86Code.Length) } | Should Not Throw
            $Session | Remove-UCEmulatorSession
        }

        It 'should not accept an invalid session' {
            { Start-UCEmulatorSession -Session $InvalidSession -StartAddress $Address -EndAddress ($Address + $X86Code.Length) } | Should Throw
        }
    }

    # Note: these are only basic tests. Additional, architecture specific regression tests should be performed as well.
    Context 'intended behavior' {
        It 'Should emulate simple opcodes correctly' {
            $EcxOld = 0x1234
            $EdxOld = 0x7890

            $Session = New-UCEmulatorSession -X86 -X86Mode MODE_32
            $Session | Initialize-UCMemoryMap -Address $Address -Size 2048KB
            $Session | Write-UCMemory -Address $Address -Data $X86Code
            $Session | Set-UCRegister -RegisterX86 ECX -Value $EcxOld
            $Session | Set-UCRegister -RegisterX86 EDX -Value $EdxOld
            $Session | Start-UCEmulatorSession -StartAddress $Address -EndAddress ($Address + $X86Code.Length)
            $EcxNew = $Session | Get-UCRegister -RegisterX86 ECX
            $EdxNew = $Session | Get-UCRegister -RegisterX86 EDX

            $EcxNew -eq ($EcxOld + 1) | Should Be $True
            $EdxNew -eq ($EdxOld - 1) | Should Be $True

            $Session | Remove-UCEmulatorSession
        }

        It 'should only execute a single instruction versus all instructions' {
            $EcxOld = 0x1234
            $EdxOld = 0x7890

            $Session = New-UCEmulatorSession -X86 -X86Mode MODE_32
            $Session | Initialize-UCMemoryMap -Address $Address -Size 2048KB
            $Session | Write-UCMemory -Address $Address -Data $X86Code
            $Session | Set-UCRegister -RegisterX86 ECX -Value $EcxOld
            $Session | Set-UCRegister -RegisterX86 EDX -Value $EdxOld
            $Session | Start-UCEmulatorSession -StartAddress $Address -EndAddress ($Address + $X86Code.Length) -Count 1
            $EcxNew = $Session | Get-UCRegister -RegisterX86 ECX
            $EdxNew = $Session | Get-UCRegister -RegisterX86 EDX

            $EcxNew -eq ($EcxOld + 1) | Should Be $True
            $EdxNew -eq $EdxOld | Should Be $True

            $Session | Remove-UCEmulatorSession
        }

        It 'should timeout from an infinite loop' {
            $InfiniteLoop = @(0xEB, 0xFE) # Jump into self - i.e. infinite loop
            $Session = New-UCEmulatorSession -X86 -X86Mode MODE_32
            $Session | Initialize-UCMemoryMap -Address $Address -Size 2048KB
            $Session | Write-UCMemory -Address $Address -Data $InfiniteLoop
            { $Session | Start-UCEmulatorSession -StartAddress $Address -EndAddress ($Address + $InfiniteLoop.Length) -Timeout 50000 } | Should Not Throw
            $Session | Remove-UCEmulatorSession
        }

        It 'should not emulate from unmapped memory' {
            $Session = New-UCEmulatorSession -X86 -X86Mode MODE_32
            $Session | Initialize-UCMemoryMap -Address $Address -Size 2048KB
            $Session | Write-UCMemory -Address $Address -Data $X86Code
            $Session | Set-UCRegister -RegisterX86 ECX -Value 0x1234
            $Session | Set-UCRegister -RegisterX86 EDX -Value 0x7890
            { Start-UCEmulatorSession -Session $Session -StartAddress 0 -EndAddress (0 + $X86Code.Length) } | Should Throw
            $Session | Remove-UCEmulatorSession
        }
    }
}

Describe 'Register-UCHook' {
    $InvalidSession = [IntPtr]::Zero

    $X86Code = @(0x41) # INC ecx
    $Address = 0x1000000

    $CodeHook = {
        param (
            [IntPtr]
            $Session,

            [UInt64]
            $Address,

            [UInt32]
            $Size
        )

        New-Event -SourceIdentifier TestHookEvent -MessageData 'Instruction executed!'
    }

    Context 'parameter validation' {
        It 'should accept a valid session over the pipeline' {
            $Session = New-UCEmulatorSession -X86 -X86Mode MODE_32
            $Session | Initialize-UCMemoryMap -Address $Address -Size 2048KB
            $Session | Write-UCMemory -Address $Address -Data $X86Code
            { $HookHandle = $Session | Register-UCHook -CodeHook -Action $CodeHook } | Should Not Throw
            $Session | Remove-UCEmulatorSession
        }

        It 'should accept a valid session argument passed as the -Session parameter' {
            $Session = New-UCEmulatorSession -X86 -X86Mode MODE_32
            $Session | Initialize-UCMemoryMap -Address $Address -Size 2048KB
            $Session | Write-UCMemory -Address $Address -Data $X86Code
            { $HookHandle = Register-UCHook -Session $Session -CodeHook -Action $CodeHook } | Should Not Throw
            $Session | Remove-UCEmulatorSession
        }

        It 'should not accept an invalid session' {
            { Register-UCHook -Session $InvalidSession -CodeHook -Action $CodeHook } | Should Throw
        }
    }

    Context 'intended behavior' {
        It 'should return a valid hook handle' {
            $Session = New-UCEmulatorSession -X86 -X86Mode MODE_32
            $Session | Initialize-UCMemoryMap -Address $Address -Size 2048KB
            $Session | Write-UCMemory -Address $Address -Data $X86Code
            $HookHandle = Register-UCHook -Session $Session -CodeHook -Action $CodeHook
            $HookHandle -is [IntPtr] | Should Be $True
            $HookHandle -ne [IntPtr]::Zero | Should Be $True
            $Session | Remove-UCEmulatorSession
        }

        It 'should execute a sample hook scriptblock' {
            $Session = New-UCEmulatorSession -X86 -X86Mode MODE_32
            $Session | Initialize-UCMemoryMap -Address $Address -Size 2048KB
            $Session | Write-UCMemory -Address $Address -Data $X86Code
            $HookHandle = Register-UCHook -Session $Session -CodeHook -Action $CodeHook

            $null = Remove-Event -SourceIdentifier TestHookEvent -ErrorAction Ignore
            $Session | Start-UCEmulatorSession -StartAddress $Address -EndAddress ($Address + $X86Code.Length)
            $HookEvent = @(Wait-Event -SourceIdentifier TestHookEvent -Timeout 10)
            $HookEvent | Should Not BeNullOrEmpty
            $HookEvent.Count -eq 1 | Should Be $True
            $HookEvent.MessageData | Should Be 'Instruction executed!'
            $HookEvent | Remove-Event -ErrorAction Ignore

            $Session | Remove-UCEmulatorSession
        }
    }
}

Describe 'Remove-UCHook' {
    $InvalidSession = [IntPtr]::Zero

    $X86Code = @(0x41) # INC ecx
    $Address = 0x1000000

    $CodeHook = {
        param (
            [IntPtr]
            $Session,

            [UInt64]
            $Address,

            [UInt32]
            $Size
        )

        New-Event -SourceIdentifier TestHookEvent -MessageData 'Instruction executed!'
    }

    Context 'parameter validation' {
        It 'should accept a valid session over the pipeline' {
            $Session = New-UCEmulatorSession -X86 -X86Mode MODE_32
            $Session | Initialize-UCMemoryMap -Address $Address -Size 2048KB
            $Session | Write-UCMemory -Address $Address -Data $X86Code
            $HookHandle = $Session | Register-UCHook -CodeHook -Action $CodeHook
            { $Session | Remove-UCHook -HookHandle $HookHandle } | Should Not Throw
            $Session | Remove-UCEmulatorSession
        }

        It 'should accept a valid session argument passed as the -Session parameter' {
            $Session = New-UCEmulatorSession -X86 -X86Mode MODE_32
            $Session | Initialize-UCMemoryMap -Address $Address -Size 2048KB
            $Session | Write-UCMemory -Address $Address -Data $X86Code
            $HookHandle = $Session | Register-UCHook -CodeHook -Action $CodeHook
            { Remove-UCHook -Session $Session -HookHandle $HookHandle } | Should Not Throw
            $Session | Remove-UCEmulatorSession
        }

        It 'should not accept an invalid session' {
            $Session = New-UCEmulatorSession -X86 -X86Mode MODE_32
            $Session | Initialize-UCMemoryMap -Address $Address -Size 2048KB
            $Session | Write-UCMemory -Address $Address -Data $X86Code
            $HookHandle = Register-UCHook -Session $Session -CodeHook -Action $CodeHook
            { Remove-UCHook -Session $InvalidSession -HookHandle $HookHandle } | Should Throw
            $Session | Remove-UCEmulatorSession
        }

        It 'should not accept an invalid hook handle' {
            $Session = New-UCEmulatorSession -X86 -X86Mode MODE_32
            $Session | Initialize-UCMemoryMap -Address $Address -Size 2048KB
            $Session | Write-UCMemory -Address $Address -Data $X86Code
            { $Session | Remove-UCHook -HookHandle ([IntPtr]::Zero) } | Should Throw
            $Session | Remove-UCEmulatorSession
        }
    }

    Context 'intended behavior' {
        It 'should clear the hook handle' {
            $Session = New-UCEmulatorSession -X86 -X86Mode MODE_32
            $Session | Initialize-UCMemoryMap -Address $Address -Size 2048KB
            $Session | Write-UCMemory -Address $Address -Data $X86Code
            $HookHandle = Register-UCHook -Session $Session -CodeHook -Action $CodeHook
            $HookHandle -is [IntPtr] | Should Be $True
            $HookHandle -ne [IntPtr]::Zero | Should Be $True
            $Session | Remove-UCHook -HookHandle $HookHandle
            $HookHandle -is [IntPtr] | Should Be $True
            $HookHandle -eq [IntPtr]::Zero | Should Be $True
            $Session | Remove-UCEmulatorSession
        }
    }
}

Describe 'New-UCHookTemplate' {
    Context 'parameter validation' {
        It 'should not output a scriptblock without a mandatory switch' {
            { New-UCHookTemplate -ErrorAction Stop } | Should throw
        }
    }

    Context 'intended behavior' {
        It 'should return a code hook scriptblock' {
            (New-UCHookTemplate -CodeHook) -is [ScriptBlock] | Should Be $True
        }

        It 'should return an interrupt hook scriptblock' {
            (New-UCHookTemplate -InterruptHook) -is [ScriptBlock] | Should Be $True
        }

        It 'should return a basic block scriptblock' {
            (New-UCHookTemplate -BasicBlockHook) -is [ScriptBlock] | Should Be $True
        }

        It 'should return a memory read hook scriptblock' {
            (New-UCHookTemplate -MemoryReadHook) -is [ScriptBlock] | Should Be $True
        }

        It 'should return a memory write hook scriptblock' {
            (New-UCHookTemplate -MemoryWriteHook) -is [ScriptBlock] | Should Be $True
        }

        It 'should return an invalid memory access scriptblock' {
            (New-UCHookTemplate -InvalidMemAccessHook) -is [ScriptBlock] | Should Be $True
        }

        It 'should return a syscall scriptblock' {
            (New-UCHookTemplate -SyscallHook) -is [ScriptBlock] | Should Be $True
        }

        It 'should return an x86 IN hook scriptblock' {
            (New-UCHookTemplate -X86InHook) -is [ScriptBlock] | Should Be $True
        }

        It 'should return an x86 OUT hook scriptblock' {
            (New-UCHookTemplate -X86OutHook) -is [ScriptBlock] | Should Be $True
        }
    }
}