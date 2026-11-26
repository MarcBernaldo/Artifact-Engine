Description: Artifact Engine - registry persistence (ASEPs)
Author: Artifact Engine
Version: 1
Id: 6f1e2a7c-9b3d-4e85-a1c4-2d7f0b9e5a31
# Category is the technique art_reg_persistence names. Curated from RECmd's
# RegistryASEPs/DFIRBatch/Kroll batches and the engine's own list (v0.7.210):
# left out, measured on clean builds and real hosts, are inventories that list
# every host's own entries and name no program (the HKLM COM catalog, SafeBoot,
# GP extensions, SvcHost groups, KnownDLLs, shell extension CLSIDs, IE add-on
# stats, SharedDLLs, per-user Active Setup markers) and what other tables read
# (services: art_reg_services; tasks: art_reg_tasks; RunMRU: art_reg_run_mru).
Keys:
    -
        Description: 'run: Microsoft\Windows\CurrentVersion\Run'
        HiveType: SOFTWARE
        Category: run
        KeyPath: 'Microsoft\Windows\CurrentVersion\Run'
        Recursive: false
        Comment: ''
    -
        Description: 'run: Microsoft\Windows\CurrentVersion\RunOnce'
        HiveType: SOFTWARE
        Category: run
        KeyPath: 'Microsoft\Windows\CurrentVersion\RunOnce'
        Recursive: false
        Comment: ''
    -
        Description: 'run: Microsoft\Windows\CurrentVersion\RunServices'
        HiveType: SOFTWARE
        Category: run
        KeyPath: 'Microsoft\Windows\CurrentVersion\RunServices'
        Recursive: false
        Comment: ''
    -
        Description: 'run: Microsoft\Windows\CurrentVersion\RunServicesOnce'
        HiveType: SOFTWARE
        Category: run
        KeyPath: 'Microsoft\Windows\CurrentVersion\RunServicesOnce'
        Recursive: false
        Comment: ''
    -
        Description: 'run: Microsoft\Windows\CurrentVersion\RunOnce\Setup'
        HiveType: SOFTWARE
        Category: run
        KeyPath: 'Microsoft\Windows\CurrentVersion\RunOnce\Setup'
        Recursive: false
        Comment: ''
    -
        Description: 'run: Microsoft\Windows\CurrentVersion\RunOnceEx'
        HiveType: SOFTWARE
        Category: run
        KeyPath: 'Microsoft\Windows\CurrentVersion\RunOnceEx'
        Recursive: true
        Comment: ''
    -
        Description: 'run: Microsoft\Windows NT\CurrentVersion\Terminal Server\install\Software\Microsoft\Windows\CurrentVersion\Run'
        HiveType: SOFTWARE
        Category: run
        KeyPath: 'Microsoft\Windows NT\CurrentVersion\Terminal Server\install\Software\Microsoft\Windows\CurrentVersion\Run'
        Recursive: false
        Comment: ''
    -
        Description: 'run: Microsoft\Windows NT\CurrentVersion\Terminal Server\install\Software\Microsoft\Windows\CurrentVersion\RunOnce'
        HiveType: SOFTWARE
        Category: run
        KeyPath: 'Microsoft\Windows NT\CurrentVersion\Terminal Server\install\Software\Microsoft\Windows\CurrentVersion\RunOnce'
        Recursive: false
        Comment: ''
    -
        Description: 'run: Microsoft\Windows NT\CurrentVersion\Terminal Server\install\Software\Microsoft\Windows\CurrentVersion\RunOnceEx'
        HiveType: SOFTWARE
        Category: run
        KeyPath: 'Microsoft\Windows NT\CurrentVersion\Terminal Server\install\Software\Microsoft\Windows\CurrentVersion\RunOnceEx'
        Recursive: false
        Comment: ''
    -
        Description: 'winlogon_userinit: Microsoft\Windows NT\CurrentVersion\Winlogon Userinit'
        HiveType: SOFTWARE
        Category: winlogon_userinit
        KeyPath: 'Microsoft\Windows NT\CurrentVersion\Winlogon'
        ValueName: 'Userinit'
        Recursive: false
        Comment: ''
    -
        Description: 'winlogon_shell: Microsoft\Windows NT\CurrentVersion\Winlogon Shell'
        HiveType: SOFTWARE
        Category: winlogon_shell
        KeyPath: 'Microsoft\Windows NT\CurrentVersion\Winlogon'
        ValueName: 'Shell'
        Recursive: false
        Comment: ''
    -
        Description: 'winlogon_hijack: Microsoft\Windows NT\CurrentVersion\Winlogon Taskman'
        HiveType: SOFTWARE
        Category: winlogon_hijack
        KeyPath: 'Microsoft\Windows NT\CurrentVersion\Winlogon'
        ValueName: 'Taskman'
        Recursive: false
        Comment: ''
    -
        Description: 'winlogon_hijack: Microsoft\Windows NT\CurrentVersion\Winlogon GinaDLL'
        HiveType: SOFTWARE
        Category: winlogon_hijack
        KeyPath: 'Microsoft\Windows NT\CurrentVersion\Winlogon'
        ValueName: 'GinaDLL'
        Recursive: false
        Comment: ''
    -
        Description: 'winlogon_hijack: Microsoft\Windows NT\CurrentVersion\Winlogon AppSetup'
        HiveType: SOFTWARE
        Category: winlogon_hijack
        KeyPath: 'Microsoft\Windows NT\CurrentVersion\Winlogon'
        ValueName: 'AppSetup'
        Recursive: false
        Comment: ''
    -
        Description: 'winlogon_hijack: Microsoft\Windows NT\CurrentVersion\Winlogon System'
        HiveType: SOFTWARE
        Category: winlogon_hijack
        KeyPath: 'Microsoft\Windows NT\CurrentVersion\Winlogon'
        ValueName: 'System'
        Recursive: false
        Comment: ''
    -
        Description: 'winlogon_hijack: Microsoft\Windows NT\CurrentVersion\Winlogon UIHost'
        HiveType: SOFTWARE
        Category: winlogon_hijack
        KeyPath: 'Microsoft\Windows NT\CurrentVersion\Winlogon'
        ValueName: 'UIHost'
        Recursive: false
        Comment: ''
    -
        Description: 'winlogon_hijack: Microsoft\Windows NT\CurrentVersion\Winlogon VMApplet'
        HiveType: SOFTWARE
        Category: winlogon_hijack
        KeyPath: 'Microsoft\Windows NT\CurrentVersion\Winlogon'
        ValueName: 'VMApplet'
        Recursive: false
        Comment: ''
    -
        Description: 'winlogon_hijack: Microsoft\Windows NT\CurrentVersion\Winlogon mpnotify'
        HiveType: SOFTWARE
        Category: winlogon_hijack
        KeyPath: 'Microsoft\Windows NT\CurrentVersion\Winlogon'
        ValueName: 'mpnotify'
        Recursive: false
        Comment: ''
    -
        Description: 'appinit_dlls: Microsoft\Windows NT\CurrentVersion\Windows AppInit_DLLs'
        HiveType: SOFTWARE
        Category: appinit_dlls
        KeyPath: 'Microsoft\Windows NT\CurrentVersion\Windows'
        ValueName: 'AppInit_DLLs'
        Recursive: false
        Comment: ''
    -
        Description: 'appinit_dlls: Microsoft\Windows NT\CurrentVersion\Windows LoadAppInit_DLLs'
        HiveType: SOFTWARE
        Category: appinit_dlls
        KeyPath: 'Microsoft\Windows NT\CurrentVersion\Windows'
        ValueName: 'LoadAppInit_DLLs'
        Recursive: false
        Comment: ''
    -
        Description: 'appinit_dlls: Microsoft\Windows NT\CurrentVersion\Windows Load'
        HiveType: SOFTWARE
        Category: appinit_dlls
        KeyPath: 'Microsoft\Windows NT\CurrentVersion\Windows'
        ValueName: 'Load'
        Recursive: false
        Comment: ''
    -
        Description: 'appinit_dlls: Microsoft\Windows NT\CurrentVersion\Windows Run'
        HiveType: SOFTWARE
        Category: appinit_dlls
        KeyPath: 'Microsoft\Windows NT\CurrentVersion\Windows'
        ValueName: 'Run'
        Recursive: false
        Comment: ''
    -
        Description: 'ifeo_debugger: Microsoft\Windows NT\CurrentVersion\Image File Execution Options\* Debugger'
        HiveType: SOFTWARE
        Category: ifeo_debugger
        KeyPath: 'Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*'
        ValueName: 'Debugger'
        Recursive: false
        Comment: ''
    -
        Description: 'ifeo_globalflag: Microsoft\Windows NT\CurrentVersion\Image File Execution Options\* GlobalFlag'
        HiveType: SOFTWARE
        Category: ifeo_globalflag
        KeyPath: 'Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*'
        ValueName: 'GlobalFlag'
        Recursive: false
        Comment: ''
    -
        Description: 'ifeo_verifierdlls: Microsoft\Windows NT\CurrentVersion\Image File Execution Options\* VerifierDlls'
        HiveType: SOFTWARE
        Category: ifeo_verifierdlls
        KeyPath: 'Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*'
        ValueName: 'VerifierDlls'
        Recursive: false
        Comment: ''
    -
        Description: 'silent_process_exit: Microsoft\Windows NT\CurrentVersion\SilentProcessExit\* MonitorProcess'
        HiveType: SOFTWARE
        Category: silent_process_exit
        KeyPath: 'Microsoft\Windows NT\CurrentVersion\SilentProcessExit\*'
        ValueName: 'MonitorProcess'
        Recursive: false
        Comment: ''
    -
        Description: 'aedebug: Microsoft\Windows NT\CurrentVersion\AeDebug Debugger'
        HiveType: SOFTWARE
        Category: aedebug
        KeyPath: 'Microsoft\Windows NT\CurrentVersion\AeDebug'
        ValueName: 'Debugger'
        Recursive: false
        Comment: ''
    -
        Description: 'aedebug: Microsoft\.NETFramework DbgManagedDebugger'
        HiveType: SOFTWARE
        Category: aedebug
        KeyPath: 'Microsoft\.NETFramework'
        ValueName: 'DbgManagedDebugger'
        Recursive: false
        Comment: ''
    -
        Description: 'netsh_helper: Microsoft\NetSh'
        HiveType: SOFTWARE
        Category: netsh_helper
        KeyPath: 'Microsoft\NetSh'
        Recursive: false
        Comment: ''
    -
        Description: 'cmd_autorun: Microsoft\Command Processor AutoRun'
        HiveType: SOFTWARE
        Category: cmd_autorun
        KeyPath: 'Microsoft\Command Processor'
        ValueName: 'AutoRun'
        Recursive: false
        Comment: ''
    -
        Description: 'active_setup: Microsoft\Active Setup\Installed Components\* StubPath'
        HiveType: SOFTWARE
        Category: active_setup
        KeyPath: 'Microsoft\Active Setup\Installed Components\*'
        ValueName: 'StubPath'
        Recursive: false
        Comment: ''
    -
        Description: 'drivers32: Microsoft\Windows NT\CurrentVersion\Drivers32'
        HiveType: SOFTWARE
        Category: drivers32
        KeyPath: 'Microsoft\Windows NT\CurrentVersion\Drivers32'
        Recursive: false
        Comment: ''
    -
        Description: 'shim_database: Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom'
        HiveType: SOFTWARE
        Category: shim_database
        KeyPath: 'Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom'
        Recursive: true
        Comment: ''
    -
        Description: 'shim_database: Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\* DatabasePath'
        HiveType: SOFTWARE
        Category: shim_database
        KeyPath: 'Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\*'
        ValueName: 'DatabasePath'
        Recursive: false
        Comment: ''
    -
        Description: 'explorer_addin: Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects'
        HiveType: SOFTWARE
        Category: explorer_addin
        KeyPath: 'Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects'
        Recursive: true
        Comment: ''
    -
        Description: 'explorer_addin: Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks'
        HiveType: SOFTWARE
        Category: explorer_addin
        KeyPath: 'Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks'
        Recursive: true
        Comment: ''
    -
        Description: 'explorer_addin: Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler'
        HiveType: SOFTWARE
        Category: explorer_addin
        KeyPath: 'Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler'
        Recursive: true
        Comment: ''
    -
        Description: 'explorer_addin: Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects'
        HiveType: SOFTWARE
        Category: explorer_addin
        KeyPath: 'Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects'
        Recursive: true
        Comment: ''
    -
        Description: 'explorer_addin: Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad'
        HiveType: SOFTWARE
        Category: explorer_addin
        KeyPath: 'Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad'
        Recursive: false
        Comment: ''
    -
        Description: 'credential_provider: Microsoft\Windows\CurrentVersion\Authentication\Credential Providers (default)'
        HiveType: SOFTWARE
        Category: credential_provider
        KeyPath: 'Microsoft\Windows\CurrentVersion\Authentication\Credential Providers'
        ValueName: '(default)'
        Recursive: true
        Comment: ''
    -
        Description: 'credential_provider: Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters (default)'
        HiveType: SOFTWARE
        Category: credential_provider
        KeyPath: 'Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters'
        ValueName: '(default)'
        Recursive: true
        Comment: ''
    -
        Description: 'credential_provider: Microsoft\Windows\CurrentVersion\Authentication\PLAP Providers (default)'
        HiveType: SOFTWARE
        Category: credential_provider
        KeyPath: 'Microsoft\Windows\CurrentVersion\Authentication\PLAP Providers'
        ValueName: '(default)'
        Recursive: true
        Comment: ''
    -
        Description: 'office_addin: Microsoft\Office\*\Addins\* LoadBehavior'
        HiveType: SOFTWARE
        Category: office_addin
        KeyPath: 'Microsoft\Office\*\Addins\*'
        ValueName: 'LoadBehavior'
        Recursive: false
        Comment: ''
    -
        Description: 'ctf_addin: Microsoft\Ctf\LangBarAddin\* FilePath'
        HiveType: SOFTWARE
        Category: ctf_addin
        KeyPath: 'Microsoft\Ctf\LangBarAddin\*'
        ValueName: 'FilePath'
        Recursive: false
        Comment: ''
    -
        Description: 'run: Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
        HiveType: SOFTWARE
        Category: run
        KeyPath: 'Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
        Recursive: false
        Comment: ''
    -
        Description: 'run: Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
        HiveType: SOFTWARE
        Category: run
        KeyPath: 'Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
        Recursive: false
        Comment: ''
    -
        Description: 'run: Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'
        HiveType: SOFTWARE
        Category: run
        KeyPath: 'Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'
        Recursive: false
        Comment: ''
    -
        Description: 'run: Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
        HiveType: SOFTWARE
        Category: run
        KeyPath: 'Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
        Recursive: false
        Comment: ''
    -
        Description: 'run: Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce\Setup'
        HiveType: SOFTWARE
        Category: run
        KeyPath: 'Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce\Setup'
        Recursive: false
        Comment: ''
    -
        Description: 'run: Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx'
        HiveType: SOFTWARE
        Category: run
        KeyPath: 'Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx'
        Recursive: true
        Comment: ''
    -
        Description: 'run: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Terminal Server\install\Software\Microsoft\Windows\CurrentVersion\Run'
        HiveType: SOFTWARE
        Category: run
        KeyPath: 'Wow6432Node\Microsoft\Windows NT\CurrentVersion\Terminal Server\install\Software\Microsoft\Windows\CurrentVersion\Run'
        Recursive: false
        Comment: ''
    -
        Description: 'run: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Terminal Server\install\Software\Microsoft\Windows\CurrentVersion\RunOnce'
        HiveType: SOFTWARE
        Category: run
        KeyPath: 'Wow6432Node\Microsoft\Windows NT\CurrentVersion\Terminal Server\install\Software\Microsoft\Windows\CurrentVersion\RunOnce'
        Recursive: false
        Comment: ''
    -
        Description: 'run: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Terminal Server\install\Software\Microsoft\Windows\CurrentVersion\RunOnceEx'
        HiveType: SOFTWARE
        Category: run
        KeyPath: 'Wow6432Node\Microsoft\Windows NT\CurrentVersion\Terminal Server\install\Software\Microsoft\Windows\CurrentVersion\RunOnceEx'
        Recursive: false
        Comment: ''
    -
        Description: 'winlogon_userinit: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon Userinit'
        HiveType: SOFTWARE
        Category: winlogon_userinit
        KeyPath: 'Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon'
        ValueName: 'Userinit'
        Recursive: false
        Comment: ''
    -
        Description: 'winlogon_shell: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon Shell'
        HiveType: SOFTWARE
        Category: winlogon_shell
        KeyPath: 'Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon'
        ValueName: 'Shell'
        Recursive: false
        Comment: ''
    -
        Description: 'winlogon_hijack: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon Taskman'
        HiveType: SOFTWARE
        Category: winlogon_hijack
        KeyPath: 'Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon'
        ValueName: 'Taskman'
        Recursive: false
        Comment: ''
    -
        Description: 'winlogon_hijack: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon GinaDLL'
        HiveType: SOFTWARE
        Category: winlogon_hijack
        KeyPath: 'Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon'
        ValueName: 'GinaDLL'
        Recursive: false
        Comment: ''
    -
        Description: 'winlogon_hijack: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon AppSetup'
        HiveType: SOFTWARE
        Category: winlogon_hijack
        KeyPath: 'Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon'
        ValueName: 'AppSetup'
        Recursive: false
        Comment: ''
    -
        Description: 'winlogon_hijack: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon System'
        HiveType: SOFTWARE
        Category: winlogon_hijack
        KeyPath: 'Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon'
        ValueName: 'System'
        Recursive: false
        Comment: ''
    -
        Description: 'winlogon_hijack: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon UIHost'
        HiveType: SOFTWARE
        Category: winlogon_hijack
        KeyPath: 'Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon'
        ValueName: 'UIHost'
        Recursive: false
        Comment: ''
    -
        Description: 'winlogon_hijack: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon VMApplet'
        HiveType: SOFTWARE
        Category: winlogon_hijack
        KeyPath: 'Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon'
        ValueName: 'VMApplet'
        Recursive: false
        Comment: ''
    -
        Description: 'winlogon_hijack: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon mpnotify'
        HiveType: SOFTWARE
        Category: winlogon_hijack
        KeyPath: 'Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon'
        ValueName: 'mpnotify'
        Recursive: false
        Comment: ''
    -
        Description: 'appinit_dlls: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows AppInit_DLLs'
        HiveType: SOFTWARE
        Category: appinit_dlls
        KeyPath: 'Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows'
        ValueName: 'AppInit_DLLs'
        Recursive: false
        Comment: ''
    -
        Description: 'appinit_dlls: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows LoadAppInit_DLLs'
        HiveType: SOFTWARE
        Category: appinit_dlls
        KeyPath: 'Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows'
        ValueName: 'LoadAppInit_DLLs'
        Recursive: false
        Comment: ''
    -
        Description: 'appinit_dlls: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows Load'
        HiveType: SOFTWARE
        Category: appinit_dlls
        KeyPath: 'Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows'
        ValueName: 'Load'
        Recursive: false
        Comment: ''
    -
        Description: 'appinit_dlls: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows Run'
        HiveType: SOFTWARE
        Category: appinit_dlls
        KeyPath: 'Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows'
        ValueName: 'Run'
        Recursive: false
        Comment: ''
    -
        Description: 'ifeo_debugger: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\* Debugger'
        HiveType: SOFTWARE
        Category: ifeo_debugger
        KeyPath: 'Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*'
        ValueName: 'Debugger'
        Recursive: false
        Comment: ''
    -
        Description: 'ifeo_globalflag: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\* GlobalFlag'
        HiveType: SOFTWARE
        Category: ifeo_globalflag
        KeyPath: 'Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*'
        ValueName: 'GlobalFlag'
        Recursive: false
        Comment: ''
    -
        Description: 'ifeo_verifierdlls: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\* VerifierDlls'
        HiveType: SOFTWARE
        Category: ifeo_verifierdlls
        KeyPath: 'Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*'
        ValueName: 'VerifierDlls'
        Recursive: false
        Comment: ''
    -
        Description: 'silent_process_exit: Wow6432Node\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\* MonitorProcess'
        HiveType: SOFTWARE
        Category: silent_process_exit
        KeyPath: 'Wow6432Node\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\*'
        ValueName: 'MonitorProcess'
        Recursive: false
        Comment: ''
    -
        Description: 'aedebug: Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug Debugger'
        HiveType: SOFTWARE
        Category: aedebug
        KeyPath: 'Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug'
        ValueName: 'Debugger'
        Recursive: false
        Comment: ''
    -
        Description: 'aedebug: Wow6432Node\Microsoft\.NETFramework DbgManagedDebugger'
        HiveType: SOFTWARE
        Category: aedebug
        KeyPath: 'Wow6432Node\Microsoft\.NETFramework'
        ValueName: 'DbgManagedDebugger'
        Recursive: false
        Comment: ''
    -
        Description: 'netsh_helper: Wow6432Node\Microsoft\NetSh'
        HiveType: SOFTWARE
        Category: netsh_helper
        KeyPath: 'Wow6432Node\Microsoft\NetSh'
        Recursive: false
        Comment: ''
    -
        Description: 'cmd_autorun: Wow6432Node\Microsoft\Command Processor AutoRun'
        HiveType: SOFTWARE
        Category: cmd_autorun
        KeyPath: 'Wow6432Node\Microsoft\Command Processor'
        ValueName: 'AutoRun'
        Recursive: false
        Comment: ''
    -
        Description: 'active_setup: Wow6432Node\Microsoft\Active Setup\Installed Components\* StubPath'
        HiveType: SOFTWARE
        Category: active_setup
        KeyPath: 'Wow6432Node\Microsoft\Active Setup\Installed Components\*'
        ValueName: 'StubPath'
        Recursive: false
        Comment: ''
    -
        Description: 'drivers32: Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32'
        HiveType: SOFTWARE
        Category: drivers32
        KeyPath: 'Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32'
        Recursive: false
        Comment: ''
    -
        Description: 'shim_database: Wow6432Node\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom'
        HiveType: SOFTWARE
        Category: shim_database
        KeyPath: 'Wow6432Node\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom'
        Recursive: true
        Comment: ''
    -
        Description: 'shim_database: Wow6432Node\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\* DatabasePath'
        HiveType: SOFTWARE
        Category: shim_database
        KeyPath: 'Wow6432Node\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\*'
        ValueName: 'DatabasePath'
        Recursive: false
        Comment: ''
    -
        Description: 'explorer_addin: Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects'
        HiveType: SOFTWARE
        Category: explorer_addin
        KeyPath: 'Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects'
        Recursive: true
        Comment: ''
    -
        Description: 'explorer_addin: Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks'
        HiveType: SOFTWARE
        Category: explorer_addin
        KeyPath: 'Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks'
        Recursive: true
        Comment: ''
    -
        Description: 'explorer_addin: Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler'
        HiveType: SOFTWARE
        Category: explorer_addin
        KeyPath: 'Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler'
        Recursive: true
        Comment: ''
    -
        Description: 'explorer_addin: Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects'
        HiveType: SOFTWARE
        Category: explorer_addin
        KeyPath: 'Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects'
        Recursive: true
        Comment: ''
    -
        Description: 'explorer_addin: Wow6432Node\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad'
        HiveType: SOFTWARE
        Category: explorer_addin
        KeyPath: 'Wow6432Node\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad'
        Recursive: false
        Comment: ''
    -
        Description: 'credential_provider: Wow6432Node\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers (default)'
        HiveType: SOFTWARE
        Category: credential_provider
        KeyPath: 'Wow6432Node\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers'
        ValueName: '(default)'
        Recursive: true
        Comment: ''
    -
        Description: 'credential_provider: Wow6432Node\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters (default)'
        HiveType: SOFTWARE
        Category: credential_provider
        KeyPath: 'Wow6432Node\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters'
        ValueName: '(default)'
        Recursive: true
        Comment: ''
    -
        Description: 'credential_provider: Wow6432Node\Microsoft\Windows\CurrentVersion\Authentication\PLAP Providers (default)'
        HiveType: SOFTWARE
        Category: credential_provider
        KeyPath: 'Wow6432Node\Microsoft\Windows\CurrentVersion\Authentication\PLAP Providers'
        ValueName: '(default)'
        Recursive: true
        Comment: ''
    -
        Description: 'office_addin: Wow6432Node\Microsoft\Office\*\Addins\* LoadBehavior'
        HiveType: SOFTWARE
        Category: office_addin
        KeyPath: 'Wow6432Node\Microsoft\Office\*\Addins\*'
        ValueName: 'LoadBehavior'
        Recursive: false
        Comment: ''
    -
        Description: 'ctf_addin: Wow6432Node\Microsoft\Ctf\LangBarAddin\* FilePath'
        HiveType: SOFTWARE
        Category: ctf_addin
        KeyPath: 'Wow6432Node\Microsoft\Ctf\LangBarAddin\*'
        ValueName: 'FilePath'
        Recursive: false
        Comment: ''
    -
        Description: 'run: Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
        HiveType: SOFTWARE
        Category: run
        KeyPath: 'Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
        Recursive: false
        Comment: ''
    -
        Description: 'policies_system: Microsoft\Windows\CurrentVersion\Policies\System Shell'
        HiveType: SOFTWARE
        Category: policies_system
        KeyPath: 'Microsoft\Windows\CurrentVersion\Policies\System'
        ValueName: 'Shell'
        Recursive: false
        Comment: ''
    -
        Description: 'policies_system: Microsoft\Windows\CurrentVersion\Policies\System Userinit'
        HiveType: SOFTWARE
        Category: policies_system
        KeyPath: 'Microsoft\Windows\CurrentVersion\Policies\System'
        ValueName: 'Userinit'
        Recursive: false
        Comment: ''
    -
        Description: 'policies_system: Microsoft\Windows\CurrentVersion\Policies\System UIHost'
        HiveType: SOFTWARE
        Category: policies_system
        KeyPath: 'Microsoft\Windows\CurrentVersion\Policies\System'
        ValueName: 'UIHost'
        Recursive: false
        Comment: ''
    -
        Description: 'winlogon_notify: Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\* DllName'
        HiveType: SOFTWARE
        Category: winlogon_notify
        KeyPath: 'Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\*'
        ValueName: 'DllName'
        Recursive: false
        Comment: ''
    -
        Description: 'hidden_account: Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
        HiveType: SOFTWARE
        Category: hidden_account
        KeyPath: 'Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
        Recursive: false
        Comment: ''
    -
        Description: 'wer_debugger: Microsoft\Windows\Windows Error Reporting\Hangs Debugger'
        HiveType: SOFTWARE
        Category: wer_debugger
        KeyPath: 'Microsoft\Windows\Windows Error Reporting\Hangs'
        ValueName: 'Debugger'
        Recursive: false
        Comment: ''
    -
        Description: 'wer_debugger: Microsoft\Windows\Windows Error Reporting\RuntimeExceptionHelperModules'
        HiveType: SOFTWARE
        Category: wer_debugger
        KeyPath: 'Microsoft\Windows\Windows Error Reporting\RuntimeExceptionHelperModules'
        Recursive: false
        Comment: ''
    -
        Description: 'amsi_provider: Microsoft\AMSI\Providers'
        HiveType: SOFTWARE
        Category: amsi_provider
        KeyPath: 'Microsoft\AMSI\Providers'
        Recursive: true
        Comment: ''
    -
        Description: 'gp_script: Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\*\* Script'
        HiveType: SOFTWARE
        Category: gp_script
        KeyPath: 'Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\*\*'
        ValueName: 'Script'
        Recursive: false
        Comment: ''
    -
        Description: 'gp_script: Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Shutdown\*\* Script'
        HiveType: SOFTWARE
        Category: gp_script
        KeyPath: 'Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Shutdown\*\*'
        ValueName: 'Script'
        Recursive: false
        Comment: ''
    -
        Description: 'gp_script: Policies\Microsoft\Windows\System\Scripts'
        HiveType: SOFTWARE
        Category: gp_script
        KeyPath: 'Policies\Microsoft\Windows\System\Scripts'
        Recursive: true
        Comment: ''
    -
        Description: 'startup_folder: Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders Common Startup'
        HiveType: SOFTWARE
        Category: startup_folder
        KeyPath: 'Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
        ValueName: 'Common Startup'
        Recursive: false
        Comment: ''
    -
        Description: 'startup_folder: Microsoft\Windows\CurrentVersion\Explorer\Shell Folders Common Startup'
        HiveType: SOFTWARE
        Category: startup_folder
        KeyPath: 'Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'
        ValueName: 'Common Startup'
        Recursive: false
        Comment: ''
    -
        Description: 'startup_approved: Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
        HiveType: SOFTWARE
        Category: startup_approved
        KeyPath: 'Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
        Recursive: false
        Comment: ''
    -
        Description: 'startup_approved: Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32'
        HiveType: SOFTWARE
        Category: startup_approved
        KeyPath: 'Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32'
        Recursive: false
        Comment: ''
    -
        Description: 'startup_approved: Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'
        HiveType: SOFTWARE
        Category: startup_approved
        KeyPath: 'Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'
        Recursive: false
        Comment: ''
    -
        Description: 'office_test: Microsoft\Office test\Special\Perf'
        HiveType: SOFTWARE
        Category: office_test
        KeyPath: 'Microsoft\Office test\Special\Perf'
        Recursive: false
        Comment: ''
    -
        Description: 'browser_extension: Policies\Google\Chrome\ExtensionInstallForcelist'
        HiveType: SOFTWARE
        Category: browser_extension
        KeyPath: 'Policies\Google\Chrome\ExtensionInstallForcelist'
        Recursive: false
        Comment: ''
    -
        Description: 'browser_extension: Policies\Microsoft\Edge\ExtensionInstallForcelist'
        HiveType: SOFTWARE
        Category: browser_extension
        KeyPath: 'Policies\Microsoft\Edge\ExtensionInstallForcelist'
        Recursive: false
        Comment: ''
    -
        Description: 'browser_extension: Google\Chrome\Extensions\* path'
        HiveType: SOFTWARE
        Category: browser_extension
        KeyPath: 'Google\Chrome\Extensions\*'
        ValueName: 'path'
        Recursive: false
        Comment: ''
    -
        Description: 'browser_extension: Wow6432Node\Google\Chrome\Extensions\* path'
        HiveType: SOFTWARE
        Category: browser_extension
        KeyPath: 'Wow6432Node\Google\Chrome\Extensions\*'
        ValueName: 'path'
        Recursive: false
        Comment: ''
    -
        Description: 'browser_command: Clients\StartMenuInternet\*\shell\open\command (default)'
        HiveType: SOFTWARE
        Category: browser_command
        KeyPath: 'Clients\StartMenuInternet\*\shell\open\command'
        ValueName: '(default)'
        Recursive: false
        Comment: ''
    -
        Description: 'file_handler: Classes\exefile\shell\open\command (default)'
        HiveType: SOFTWARE
        Category: file_handler
        KeyPath: 'Classes\exefile\shell\open\command'
        ValueName: '(default)'
        Recursive: false
        Comment: ''
    -
        Description: 'file_handler: Classes\cmdfile\shell\open\command (default)'
        HiveType: SOFTWARE
        Category: file_handler
        KeyPath: 'Classes\cmdfile\shell\open\command'
        ValueName: '(default)'
        Recursive: false
        Comment: ''
    -
        Description: 'file_handler: Classes\batfile\shell\open\command (default)'
        HiveType: SOFTWARE
        Category: file_handler
        KeyPath: 'Classes\batfile\shell\open\command'
        ValueName: '(default)'
        Recursive: false
        Comment: ''
    -
        Description: 'file_handler: Classes\comfile\shell\open\command (default)'
        HiveType: SOFTWARE
        Category: file_handler
        KeyPath: 'Classes\comfile\shell\open\command'
        ValueName: '(default)'
        Recursive: false
        Comment: ''
    -
        Description: 'file_handler: Classes\htmlfile\shell\open\command (default)'
        HiveType: SOFTWARE
        Category: file_handler
        KeyPath: 'Classes\htmlfile\shell\open\command'
        ValueName: '(default)'
        Recursive: false
        Comment: ''
    -
        Description: 'proxy_pac: Microsoft\Windows\CurrentVersion\Internet Settings AutoConfigURL'
        HiveType: SOFTWARE
        Category: proxy_pac
        KeyPath: 'Microsoft\Windows\CurrentVersion\Internet Settings'
        ValueName: 'AutoConfigURL'
        Recursive: false
        Comment: ''
    -
        Description: 'crypto_offload: Microsoft\Cryptography\Offload ExpoOffload'
        HiveType: SOFTWARE
        Category: crypto_offload
        KeyPath: 'Microsoft\Cryptography\Offload'
        ValueName: 'ExpoOffload'
        Recursive: false
        Comment: ''
    -
        Description: 'The control set in use (only its rows are kept)'
        HiveType: SYSTEM
        Category: control_set
        KeyPath: 'Select'
        ValueName: 'Current'
        Recursive: false
        Comment: ''
    -
        Description: 'lsa_package: ControlSet*\Control\Lsa Authentication Packages'
        HiveType: SYSTEM
        Category: lsa_package
        KeyPath: 'ControlSet*\Control\Lsa'
        ValueName: 'Authentication Packages'
        Recursive: false
        Comment: ''
    -
        Description: 'lsa_package: ControlSet*\Control\Lsa Notification Packages'
        HiveType: SYSTEM
        Category: lsa_package
        KeyPath: 'ControlSet*\Control\Lsa'
        ValueName: 'Notification Packages'
        Recursive: false
        Comment: ''
    -
        Description: 'lsa_package: ControlSet*\Control\Lsa Security Packages'
        HiveType: SYSTEM
        Category: lsa_package
        KeyPath: 'ControlSet*\Control\Lsa'
        ValueName: 'Security Packages'
        Recursive: false
        Comment: ''
    -
        Description: 'lsa_package: ControlSet*\Control\Lsa\OSConfig Security Packages'
        HiveType: SYSTEM
        Category: lsa_package
        KeyPath: 'ControlSet*\Control\Lsa\OSConfig'
        ValueName: 'Security Packages'
        Recursive: false
        Comment: ''
    -
        Description: 'lsa_package: ControlSet*\Control\SecurityProviders SecurityProviders'
        HiveType: SYSTEM
        Category: lsa_package
        KeyPath: 'ControlSet*\Control\SecurityProviders'
        ValueName: 'SecurityProviders'
        Recursive: false
        Comment: ''
    -
        Description: 'bootexecute: ControlSet*\Control\Session Manager BootExecute'
        HiveType: SYSTEM
        Category: bootexecute
        KeyPath: 'ControlSet*\Control\Session Manager'
        ValueName: 'BootExecute'
        Recursive: false
        Comment: ''
    -
        Description: 'bootexecute: ControlSet*\Control\Session Manager BootShell'
        HiveType: SYSTEM
        Category: bootexecute
        KeyPath: 'ControlSet*\Control\Session Manager'
        ValueName: 'BootShell'
        Recursive: false
        Comment: ''
    -
        Description: 'bootexecute: ControlSet*\Control\Session Manager SetupExecute'
        HiveType: SYSTEM
        Category: bootexecute
        KeyPath: 'ControlSet*\Control\Session Manager'
        ValueName: 'SetupExecute'
        Recursive: false
        Comment: ''
    -
        Description: 'bootexecute: ControlSet*\Control\Session Manager Execute'
        HiveType: SYSTEM
        Category: bootexecute
        KeyPath: 'ControlSet*\Control\Session Manager'
        ValueName: 'Execute'
        Recursive: false
        Comment: ''
    -
        Description: 'bootexecute: ControlSet*\Control\Session Manager InitialCommand'
        HiveType: SYSTEM
        Category: bootexecute
        KeyPath: 'ControlSet*\Control\Session Manager'
        ValueName: 'InitialCommand'
        Recursive: false
        Comment: ''
    -
        Description: 'bootexecute: ControlSet*\Control\Session Manager PendingFileRenameOperations'
        HiveType: SYSTEM
        Category: bootexecute
        KeyPath: 'ControlSet*\Control\Session Manager'
        ValueName: 'PendingFileRenameOperations'
        Recursive: false
        Comment: ''
    -
        Description: 'appcert_dlls: ControlSet*\Control\Session Manager\AppCertDlls'
        HiveType: SYSTEM
        Category: appcert_dlls
        KeyPath: 'ControlSet*\Control\Session Manager\AppCertDlls'
        Recursive: false
        Comment: ''
    -
        Description: 'cor_profiler: ControlSet*\Control\Session Manager\Environment COR_PROFILER'
        HiveType: SYSTEM
        Category: cor_profiler
        KeyPath: 'ControlSet*\Control\Session Manager\Environment'
        ValueName: 'COR_PROFILER'
        Recursive: false
        Comment: ''
    -
        Description: 'cor_profiler: ControlSet*\Control\Session Manager\Environment COR_PROFILER_PATH'
        HiveType: SYSTEM
        Category: cor_profiler
        KeyPath: 'ControlSet*\Control\Session Manager\Environment'
        ValueName: 'COR_PROFILER_PATH'
        Recursive: false
        Comment: ''
    -
        Description: 'cor_profiler: ControlSet*\Control\Session Manager\Environment COR_ENABLE_PROFILING'
        HiveType: SYSTEM
        Category: cor_profiler
        KeyPath: 'ControlSet*\Control\Session Manager\Environment'
        ValueName: 'COR_ENABLE_PROFILING'
        Recursive: false
        Comment: ''
    -
        Description: 'scm_extension: ControlSet*\Control ServiceControlManagerExtension'
        HiveType: SYSTEM
        Category: scm_extension
        KeyPath: 'ControlSet*\Control'
        ValueName: 'ServiceControlManagerExtension'
        Recursive: false
        Comment: ''
    -
        Description: 'scm_extension: ControlSet*\Control\BootVerificationProgram ImagePath'
        HiveType: SYSTEM
        Category: scm_extension
        KeyPath: 'ControlSet*\Control\BootVerificationProgram'
        ValueName: 'ImagePath'
        Recursive: false
        Comment: ''
    -
        Description: 'print_monitor: ControlSet*\Control\Print\Monitors\* Driver'
        HiveType: SYSTEM
        Category: print_monitor
        KeyPath: 'ControlSet*\Control\Print\Monitors\*'
        ValueName: 'Driver'
        Recursive: false
        Comment: ''
    -
        Description: 'print_processor: ControlSet*\Control\Print\Environments\*\Print Processors\* Driver'
        HiveType: SYSTEM
        Category: print_processor
        KeyPath: 'ControlSet*\Control\Print\Environments\*\Print Processors\*'
        ValueName: 'Driver'
        Recursive: false
        Comment: ''
    -
        Description: 'network_provider: ControlSet*\Control\NetworkProvider\Order ProviderOrder'
        HiveType: SYSTEM
        Category: network_provider
        KeyPath: 'ControlSet*\Control\NetworkProvider\Order'
        ValueName: 'ProviderOrder'
        Recursive: false
        Comment: ''
    -
        Description: 'network_provider: ControlSet*\Services\*\NetworkProvider ProviderPath'
        HiveType: SYSTEM
        Category: network_provider
        KeyPath: 'ControlSet*\Services\*\NetworkProvider'
        ValueName: 'ProviderPath'
        Recursive: false
        Comment: ''
    -
        Description: 'time_provider: ControlSet*\Services\W32Time\TimeProviders\* DllName'
        HiveType: SYSTEM
        Category: time_provider
        KeyPath: 'ControlSet*\Services\W32Time\TimeProviders\*'
        ValueName: 'DllName'
        Recursive: false
        Comment: ''
    -
        Description: 'safeboot_shell: ControlSet*\Control\SafeBoot AlternateShell'
        HiveType: SYSTEM
        Category: safeboot_shell
        KeyPath: 'ControlSet*\Control\SafeBoot'
        ValueName: 'AlternateShell'
        Recursive: false
        Comment: ''
    -
        Description: 'rdp_startup: ControlSet*\Control\Terminal Server\Wds\rdpwd StartupPrograms'
        HiveType: SYSTEM
        Category: rdp_startup
        KeyPath: 'ControlSet*\Control\Terminal Server\Wds\rdpwd'
        ValueName: 'StartupPrograms'
        Recursive: false
        Comment: ''
    -
        Description: 'rdp_startup: ControlSet*\Control\Terminal Server\WinStations\RDP-Tcp InitialProgram'
        HiveType: SYSTEM
        Category: rdp_startup
        KeyPath: 'ControlSet*\Control\Terminal Server\WinStations\RDP-Tcp'
        ValueName: 'InitialProgram'
        Recursive: false
        Comment: ''
    -
        Description: 'natural_language: ControlSet*\Control\ContentIndex\Language\* StemmerDLLPathOverride'
        HiveType: SYSTEM
        Category: natural_language
        KeyPath: 'ControlSet*\Control\ContentIndex\Language\*'
        ValueName: 'StemmerDLLPathOverride'
        Recursive: false
        Comment: ''
    -
        Description: 'natural_language: ControlSet*\Control\ContentIndex\Language\* WBDLLPathOverride'
        HiveType: SYSTEM
        Category: natural_language
        KeyPath: 'ControlSet*\Control\ContentIndex\Language\*'
        ValueName: 'WBDLLPathOverride'
        Recursive: false
        Comment: ''
    -
        Description: 'dns_plugin: ControlSet*\Services\DNS\Parameters ServerLevelPluginDll'
        HiveType: SYSTEM
        Category: dns_plugin
        KeyPath: 'ControlSet*\Services\DNS\Parameters'
        ValueName: 'ServerLevelPluginDll'
        Recursive: false
        Comment: ''
    -
        Description: 'ntds_extension: ControlSet*\Services\NTDS DirectoryServiceExtPt'
        HiveType: SYSTEM
        Category: ntds_extension
        KeyPath: 'ControlSet*\Services\NTDS'
        ValueName: 'DirectoryServiceExtPt'
        Recursive: false
        Comment: ''
    -
        Description: 'ntds_extension: ControlSet*\Services\NTDS LsaDbExtPt'
        HiveType: SYSTEM
        Category: ntds_extension
        KeyPath: 'ControlSet*\Services\NTDS'
        ValueName: 'LsaDbExtPt'
        Recursive: false
        Comment: ''
    -
        Description: 'port_proxy: ControlSet*\Services\PortProxy\v4tov4\tcp'
        HiveType: SYSTEM
        Category: port_proxy
        KeyPath: 'ControlSet*\Services\PortProxy\v4tov4\tcp'
        Recursive: false
        Comment: ''
    -
        Description: 'port_proxy: ControlSet*\Services\PortProxy\v4tov6\tcp'
        HiveType: SYSTEM
        Category: port_proxy
        KeyPath: 'ControlSet*\Services\PortProxy\v4tov6\tcp'
        Recursive: false
        Comment: ''
    -
        Description: 'port_proxy: ControlSet*\Services\PortProxy\v6tov4\tcp'
        HiveType: SYSTEM
        Category: port_proxy
        KeyPath: 'ControlSet*\Services\PortProxy\v6tov4\tcp'
        Recursive: false
        Comment: ''
    -
        Description: 'port_proxy: ControlSet*\Services\PortProxy\v6tov6\tcp'
        HiveType: SYSTEM
        Category: port_proxy
        KeyPath: 'ControlSet*\Services\PortProxy\v6tov6\tcp'
        Recursive: false
        Comment: ''
    -
        Description: 'winsock_provider: ControlSet*\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries\* LibraryPath'
        HiveType: SYSTEM
        Category: winsock_provider
        KeyPath: 'ControlSet*\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries\*'
        ValueName: 'LibraryPath'
        Recursive: false
        Comment: ''
    -
        Description: 'winsock_provider: ControlSet*\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries64\* LibraryPath'
        HiveType: SYSTEM
        Category: winsock_provider
        KeyPath: 'ControlSet*\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries64\*'
        ValueName: 'LibraryPath'
        Recursive: false
        Comment: ''
    -
        Description: 'setup_cmdline: Setup CmdLine'
        HiveType: SYSTEM
        Category: setup_cmdline
        KeyPath: 'Setup'
        ValueName: 'CmdLine'
        Recursive: false
        Comment: ''
    -
        Description: 'run: Software\Microsoft\Windows\CurrentVersion\Run'
        HiveType: NTUSER
        Category: run
        KeyPath: 'Software\Microsoft\Windows\CurrentVersion\Run'
        Recursive: false
        Comment: ''
    -
        Description: 'run: Software\Microsoft\Windows\CurrentVersion\RunOnce'
        HiveType: NTUSER
        Category: run
        KeyPath: 'Software\Microsoft\Windows\CurrentVersion\RunOnce'
        Recursive: false
        Comment: ''
    -
        Description: 'run: Software\Microsoft\Windows\CurrentVersion\RunServices'
        HiveType: NTUSER
        Category: run
        KeyPath: 'Software\Microsoft\Windows\CurrentVersion\RunServices'
        Recursive: false
        Comment: ''
    -
        Description: 'run: Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
        HiveType: NTUSER
        Category: run
        KeyPath: 'Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
        Recursive: false
        Comment: ''
    -
        Description: 'run: Software\Microsoft\Windows\CurrentVersion\RunOnceEx'
        HiveType: NTUSER
        Category: run
        KeyPath: 'Software\Microsoft\Windows\CurrentVersion\RunOnceEx'
        Recursive: true
        Comment: ''
    -
        Description: 'cmd_autorun: Software\Microsoft\Command Processor AutoRun'
        HiveType: NTUSER
        Category: cmd_autorun
        KeyPath: 'Software\Microsoft\Command Processor'
        ValueName: 'AutoRun'
        Recursive: false
        Comment: ''
    -
        Description: 'run: Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
        HiveType: NTUSER
        Category: run
        KeyPath: 'Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
        Recursive: false
        Comment: ''
    -
        Description: 'run: Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
        HiveType: NTUSER
        Category: run
        KeyPath: 'Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
        Recursive: false
        Comment: ''
    -
        Description: 'run: Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'
        HiveType: NTUSER
        Category: run
        KeyPath: 'Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'
        Recursive: false
        Comment: ''
    -
        Description: 'run: Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
        HiveType: NTUSER
        Category: run
        KeyPath: 'Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
        Recursive: false
        Comment: ''
    -
        Description: 'run: Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx'
        HiveType: NTUSER
        Category: run
        KeyPath: 'Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx'
        Recursive: true
        Comment: ''
    -
        Description: 'cmd_autorun: Software\Wow6432Node\Microsoft\Command Processor AutoRun'
        HiveType: NTUSER
        Category: cmd_autorun
        KeyPath: 'Software\Wow6432Node\Microsoft\Command Processor'
        ValueName: 'AutoRun'
        Recursive: false
        Comment: ''
    -
        Description: 'run: Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run'
        HiveType: NTUSER
        Category: run
        KeyPath: 'Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run'
        Recursive: false
        Comment: ''
    -
        Description: 'run: Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce'
        HiveType: NTUSER
        Category: run
        KeyPath: 'Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce'
        Recursive: false
        Comment: ''
    -
        Description: 'run: Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnceEx'
        HiveType: NTUSER
        Category: run
        KeyPath: 'Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnceEx'
        Recursive: false
        Comment: ''
    -
        Description: 'appinit_dlls: Software\Microsoft\Windows NT\CurrentVersion\Windows Load'
        HiveType: NTUSER
        Category: appinit_dlls
        KeyPath: 'Software\Microsoft\Windows NT\CurrentVersion\Windows'
        ValueName: 'Load'
        Recursive: false
        Comment: ''
    -
        Description: 'appinit_dlls: Software\Microsoft\Windows NT\CurrentVersion\Windows Run'
        HiveType: NTUSER
        Category: appinit_dlls
        KeyPath: 'Software\Microsoft\Windows NT\CurrentVersion\Windows'
        ValueName: 'Run'
        Recursive: false
        Comment: ''
    -
        Description: 'winlogon_shell: Software\Microsoft\Windows NT\CurrentVersion\Winlogon Shell'
        HiveType: NTUSER
        Category: winlogon_shell
        KeyPath: 'Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
        ValueName: 'Shell'
        Recursive: false
        Comment: ''
    -
        Description: 'winlogon_userinit: Software\Microsoft\Windows NT\CurrentVersion\Winlogon Userinit'
        HiveType: NTUSER
        Category: winlogon_userinit
        KeyPath: 'Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
        ValueName: 'Userinit'
        Recursive: false
        Comment: ''
    -
        Description: 'run: Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
        HiveType: NTUSER
        Category: run
        KeyPath: 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
        Recursive: false
        Comment: ''
    -
        Description: 'policies_system: Software\Microsoft\Windows\CurrentVersion\Policies\System Shell'
        HiveType: NTUSER
        Category: policies_system
        KeyPath: 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
        ValueName: 'Shell'
        Recursive: false
        Comment: ''
    -
        Description: 'policies_system: Software\Microsoft\Windows\CurrentVersion\Policies\System Userinit'
        HiveType: NTUSER
        Category: policies_system
        KeyPath: 'Software\Microsoft\Windows\CurrentVersion\Policies\System'
        ValueName: 'Userinit'
        Recursive: false
        Comment: ''
    -
        Description: 'logon_script: Environment UserInitMprLogonScript'
        HiveType: NTUSER
        Category: logon_script
        KeyPath: 'Environment'
        ValueName: 'UserInitMprLogonScript'
        Recursive: false
        Comment: ''
    -
        Description: 'cor_profiler: Environment COR_PROFILER'
        HiveType: NTUSER
        Category: cor_profiler
        KeyPath: 'Environment'
        ValueName: 'COR_PROFILER'
        Recursive: false
        Comment: ''
    -
        Description: 'cor_profiler: Environment COR_PROFILER_PATH'
        HiveType: NTUSER
        Category: cor_profiler
        KeyPath: 'Environment'
        ValueName: 'COR_PROFILER_PATH'
        Recursive: false
        Comment: ''
    -
        Description: 'cor_profiler: Environment COR_ENABLE_PROFILING'
        HiveType: NTUSER
        Category: cor_profiler
        KeyPath: 'Environment'
        ValueName: 'COR_ENABLE_PROFILING'
        Recursive: false
        Comment: ''
    -
        Description: 'screensaver: Control Panel\Desktop SCRNSAVE.EXE'
        HiveType: NTUSER
        Category: screensaver
        KeyPath: 'Control Panel\Desktop'
        ValueName: 'SCRNSAVE.EXE'
        Recursive: false
        Comment: ''
    -
        Description: 'screensaver: Software\Policies\Microsoft\Windows\Control Panel\Desktop SCRNSAVE.EXE'
        HiveType: NTUSER
        Category: screensaver
        KeyPath: 'Software\Policies\Microsoft\Windows\Control Panel\Desktop'
        ValueName: 'SCRNSAVE.EXE'
        Recursive: false
        Comment: ''
    -
        Description: 'gp_script: Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon\*\* Script'
        HiveType: NTUSER
        Category: gp_script
        KeyPath: 'Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon\*\*'
        ValueName: 'Script'
        Recursive: false
        Comment: ''
    -
        Description: 'gp_script: Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logoff\*\* Script'
        HiveType: NTUSER
        Category: gp_script
        KeyPath: 'Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logoff\*\*'
        ValueName: 'Script'
        Recursive: false
        Comment: ''
    -
        Description: 'gp_script: Software\Policies\Microsoft\Windows\System\Scripts'
        HiveType: NTUSER
        Category: gp_script
        KeyPath: 'Software\Policies\Microsoft\Windows\System\Scripts'
        Recursive: true
        Comment: ''
    -
        Description: 'startup_folder: Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders Startup'
        HiveType: NTUSER
        Category: startup_folder
        KeyPath: 'Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
        ValueName: 'Startup'
        Recursive: false
        Comment: ''
    -
        Description: 'startup_folder: Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders Startup'
        HiveType: NTUSER
        Category: startup_folder
        KeyPath: 'Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'
        ValueName: 'Startup'
        Recursive: false
        Comment: ''
    -
        Description: 'startup_approved: Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
        HiveType: NTUSER
        Category: startup_approved
        KeyPath: 'Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
        Recursive: false
        Comment: ''
    -
        Description: 'startup_approved: Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32'
        HiveType: NTUSER
        Category: startup_approved
        KeyPath: 'Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32'
        Recursive: false
        Comment: ''
    -
        Description: 'startup_approved: Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'
        HiveType: NTUSER
        Category: startup_approved
        KeyPath: 'Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'
        Recursive: false
        Comment: ''
    -
        Description: 'explorer_addin: Software\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects'
        HiveType: NTUSER
        Category: explorer_addin
        KeyPath: 'Software\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects'
        Recursive: true
        Comment: ''
    -
        Description: 'explorer_addin: Software\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler'
        HiveType: NTUSER
        Category: explorer_addin
        KeyPath: 'Software\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler'
        Recursive: true
        Comment: ''
    -
        Description: 'explorer_addin: Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects'
        HiveType: NTUSER
        Category: explorer_addin
        KeyPath: 'Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects'
        Recursive: true
        Comment: ''
    -
        Description: 'explorer_addin: Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad'
        HiveType: NTUSER
        Category: explorer_addin
        KeyPath: 'Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad'
        Recursive: false
        Comment: ''
    -
        Description: 'office_test: Software\Microsoft\Office test\Special\Perf'
        HiveType: NTUSER
        Category: office_test
        KeyPath: 'Software\Microsoft\Office test\Special\Perf'
        Recursive: false
        Comment: ''
    -
        Description: 'office_addin: Software\Microsoft\Office\*\Addins\* LoadBehavior'
        HiveType: NTUSER
        Category: office_addin
        KeyPath: 'Software\Microsoft\Office\*\Addins\*'
        ValueName: 'LoadBehavior'
        Recursive: false
        Comment: ''
    -
        Description: 'outlook_homepage: Software\Microsoft\Office\*\Outlook\Today UserDefinedUrl'
        HiveType: NTUSER
        Category: outlook_homepage
        KeyPath: 'Software\Microsoft\Office\*\Outlook\Today'
        ValueName: 'UserDefinedUrl'
        Recursive: false
        Comment: ''
    -
        Description: 'outlook_homepage: Software\Microsoft\Office\*\Outlook\WebView\* URL'
        HiveType: NTUSER
        Category: outlook_homepage
        KeyPath: 'Software\Microsoft\Office\*\Outlook\WebView\*'
        ValueName: 'URL'
        Recursive: false
        Comment: ''
    -
        Description: 'proxy_pac: Software\Microsoft\Windows\CurrentVersion\Internet Settings AutoConfigURL'
        HiveType: NTUSER
        Category: proxy_pac
        KeyPath: 'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        ValueName: 'AutoConfigURL'
        Recursive: false
        Comment: ''
    -
        Description: 'class_hijack: ms-settings\shell\open\command'
        HiveType: USRCLASS
        Category: class_hijack
        KeyPath: 'ms-settings\shell\open\command'
        Recursive: false
        Comment: ''
    -
        Description: 'class_hijack: Folder\shell\open\command'
        HiveType: USRCLASS
        Category: class_hijack
        KeyPath: 'Folder\shell\open\command'
        Recursive: false
        Comment: ''
    -
        Description: 'class_hijack: mscfile\shell\open\command'
        HiveType: USRCLASS
        Category: class_hijack
        KeyPath: 'mscfile\shell\open\command'
        Recursive: false
        Comment: ''
    -
        Description: 'class_hijack: exefile\shell\open\command'
        HiveType: USRCLASS
        Category: class_hijack
        KeyPath: 'exefile\shell\open\command'
        Recursive: false
        Comment: ''
    -
        Description: 'class_hijack: Launcher.SystemSettings\shell\open\command'
        HiveType: USRCLASS
        Category: class_hijack
        KeyPath: 'Launcher.SystemSettings\shell\open\command'
        Recursive: false
        Comment: ''
    -
        Description: 'com_hijack: CLSID\*\InprocServer32 (default)'
        HiveType: USRCLASS
        Category: com_hijack
        KeyPath: 'CLSID\*\InprocServer32'
        ValueName: '(default)'
        Recursive: false
        Comment: ''
    -
        Description: 'com_hijack: CLSID\*\LocalServer32 (default)'
        HiveType: USRCLASS
        Category: com_hijack
        KeyPath: 'CLSID\*\LocalServer32'
        ValueName: '(default)'
        Recursive: false
        Comment: ''
    -
        Description: 'com_hijack: Wow6432Node\CLSID\*\InprocServer32 (default)'
        HiveType: USRCLASS
        Category: com_hijack
        KeyPath: 'Wow6432Node\CLSID\*\InprocServer32'
        ValueName: '(default)'
        Recursive: false
        Comment: ''
