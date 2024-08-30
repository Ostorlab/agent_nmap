When simple access control requirements suffice, you can directly specify the accessibility level using `kSecAttrAccessible`. Omitting `kSecAttrAccessControl` is acceptable in these cases.

| Use Case                                                                         | Protection                                  | 
|----------------------------------------------------------------------------------|---------------------------------------------|
| Storing data always accessible                                                   | `kSecAttrAccessibleAlways`                 | 
| Storing data accessible after first unlock                                       | `kSecAttrAccessibleAfterFirstUnlock`       | 
| Storing data only accessible when device unlocked                                | `kSecAttrAccessibleWhenUnlocked`           |

**Example**:

=== "Swift"
	```swift
	import Foundation
    import Security
    
    func saveSecretToKeychain() {
        let secretData = "mySecretPassword".data(using: .utf8)!
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "myAccount",
            kSecValueData as String: secretData,
            kSecAttrAccessible as String: kSecAttrAccessibleAlways
        ]
        SecItemAdd(query as CFDictionary, nil)
    }
    saveSecretToKeychain()
	```

For more complex security requirements, such as demanding user presence or implementing application-specific passwords, use `SecAccessControlCreateWithFlags` to create access control with additional flags.

| Use Case                                                                         | Protection                         | Flags                              | 
|----------------------------------------------------------------------------------|------------------------------------|-------------------------------------|
| Dealing with sensitive data that requires a user presence                       | `kSecAttrAccessibleWhenUnlocked`                                  | `kSecAccessControlUserPresence`    | 
| Dealing with sensitive data that requires a specific password for extra security | `kSecAttrAccessibleWhenPasscodeSet` | `kSecAccessControlApplicationPassword` |

**Example**:

=== "Swift"
	```swift
	import Foundation
    import Security
    
    func saveSecretToKeychain() {
        let secretData = "mySecretPassword".data(using: .utf8)!
        let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlocked,
            kSecAccessControlUserPresence,
            nil
        )
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "myAccount",
            kSecValueData as String: secretData,
            kSecAttrAccessControl as String: access!,
        ]
        SecItemAdd(query as CFDictionary, nil)
    }
    saveSecretToKeychain()
    ```