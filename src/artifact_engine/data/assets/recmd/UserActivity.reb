Description: Per-user program execution and file access (NTUSER.DAT)
Author: Artifact Engine
Version: 1
Id: 4f1c2a7e-9b3d-4e6a-8c5f-2d7e1b9a0c31
Keys:
    -
        Description: Compatibility Assistant Store
        HiveType: NTUSER
        Category: Program Execution
        KeyPath: Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store
        Recursive: false
        Comment: "Programs the Program Compatibility Assistant saw run (Windows 7-10)"
    -
        Description: AppCompatFlags Layers
        HiveType: NTUSER
        Category: Program Execution
        KeyPath: Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers
        Recursive: false
        Comment: "Programs set to run in a compatibility mode, or as administrator"
    -
        Description: FeatureUsage
        HiveType: NTUSER
        Category: Program Execution
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage
        Recursive: true
        Comment: "Taskbar use per program: AppSwitched, AppLaunch, ShowJumpView (Windows 10 1903+)"
    -
        Description: OpenSavePidlMRU
        HiveType: NTUSER
        Category: File and Folder Opening
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU
        Recursive: true
        Comment: "Files opened or saved through a common dialog"
    -
        Description: LastVisitedPidlMRU
        HiveType: NTUSER
        Category: Program Execution
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU
        Recursive: false
        Comment: "The program that opened a common dialog, and the folder it was left in"
    -
        Description: RecentDocs
        HiveType: NTUSER
        Category: File and Folder Opening
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
        Recursive: false
        Comment: "Files and folders the user opened from Explorer"
