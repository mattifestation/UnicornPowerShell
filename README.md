## Unicorn Engine - PowerShell Binding

A pure PowerShell binding of the Unicorn Engine. The Unicorn Engine is developed by:

Nguyen Anh Quynh <aquynh -at- gmail.com>
Dang Hoang Vu <dang.hvu -at- gmail.com>

### License

GNU GENERAL PUBLIC LICENSE - Version 2. See COPYING.

### Usage

The Unicorn Engine PowerShell binding is a PowerShell module. Load it like any other module using Import-Module.

### Compatibility

The Unicorn Engine PowerShell binding is designed to run on PowerShell version 3 and above.

### Help!!!

Currently, I am struggling with getting PowerShell scriptblock execution working with the Register-UCHook function. Due to the thread that executes the hooks not having its own runspace, PowerShell scriptblocks will not execute in the context of the thread. The ability to execute scriptblocks in response to hook events is considered a core feature of the PowerShell Unicorn binding so if someone can figure out how to get this working, I would be eternally grateful!!! Thus far, I have tried the techniques explained in the following articles:

http://www.nivot.org/post/2009/10/09/PowerShell20AsynchronousCallbacksFromNET
http://www.exploit-monday.com/2013/06/PowerShellCallbackFunctions.html

### Todo

Regression tests similar to those in the python binding need to be written. Also, if scriptblock execution ever works for instrumentation callbacks, then all hook types will need to be supported in Register-UCHook.