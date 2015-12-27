## Unicorn Engine - PowerShell Binding

A pure PowerShell binding of the Unicorn Engine. The Unicorn Engine is developed by:

Nguyen Anh Quynh: aquynh -at- gmail.com

Dang Hoang Vu: dang.hvu -at- gmail.com

### License

GNU GENERAL PUBLIC LICENSE - Version 2. See COPYING.

### Usage

The Unicorn Engine PowerShell binding is a PowerShell module. Load it like any other module using Import-Module.

### Compatibility

The Unicorn Engine PowerShell binding is designed to run on PowerShell version 3 and above.

### Known issues

Due to hook callback scriptblocks being implemented as async callbacks your registered hooks are not guaranteed to execute in order without some special handling in your emulation script. Once I figure out a generic method of forcing an order or execution, I will provide examples.