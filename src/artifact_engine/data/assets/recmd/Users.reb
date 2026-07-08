Description: Executables discovered or used
Author: Troyla
Version: 1
Id: 230a19c6-4234-459e-a4da-fb10b19e8101
Keys:
    -
        Description: User Accounts (SAM)
        HiveType: SAM
        Category: User Accounts
        KeyPath: SAM\Domains\Account\Users
        Recursive: false
        Comment: "User accounts in SAM hive"
    -
        Description: Built-in User Accounts (SAM)
        HiveType: SAM
        Category: User Accounts
        KeyPath: SAM\Domains\Builtin\Aliases
        Recursive: false
        Comment: "Built-in accounts in SAM hive"