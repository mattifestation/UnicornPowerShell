@{
# Script module or binary module file associated with this manifest.
ModuleToProcess = 'Unicorn.psm1'

# Version number of this module. This will remain in sync with the supported version of unicorn.dll
ModuleVersion = '0.9.0.0'

# ID used to uniquely identify this module
GUID = 'fff38dd9-7f65-4681-9cfb-0cf4929a8e68'

# Author of this module
Author = 'Matthew Graeber'

# Copyright statement for this module
Copyright = 'see COPYING'

# Description of the functionality provided by this module
Description = 'Unicorn Engine Binding Module'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '3.0'

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
NestedModules = @('Lib\PSReflect\PSReflect.psd1')

# Functions to export from this module
# I've chosen to explicitly the functions I want to expose rather than exporting everything or calling Export-ModuleMember
FunctionsToExport = @('Get-UCVersion',
                      'New-UCEmulatorSession',
                      'Initialize-UCMemoryMap',
                      'Remove-UCMemoryMap',
                      'Write-UCMemory',
                      'Set-UCMemoryProtection',
                      'Read-UCMemory',
                      'Set-UCRegister',
                      'Get-UCRegister',
                      'Remove-UCEmulatorSession',
                      'Start-UCEmulatorSession',
                      'Register-UCHook')

# Cmdlets to export from this module
CmdletsToExport = ''

# Variables to export from this module
VariablesToExport = ''

# Aliases to export from this module
AliasesToExport = ''
}
