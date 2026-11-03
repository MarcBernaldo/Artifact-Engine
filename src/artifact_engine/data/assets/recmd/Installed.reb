Description: Installed software (SOFTWARE)
Author: Artifact Engine
Version: 1
Id: 4f1c2a7e-9b3d-4e6a-8c5f-2d7e1b9a0c32
Keys:
    -
        Description: Uninstall
        HiveType: SOFTWARE
        Category: Installed Software
        KeyPath: Microsoft\Windows\CurrentVersion\Uninstall
        Recursive: false
    -
        Description: Uninstall (32-bit)
        HiveType: SOFTWARE
        Category: Installed Software
        KeyPath: WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall
        Recursive: false
