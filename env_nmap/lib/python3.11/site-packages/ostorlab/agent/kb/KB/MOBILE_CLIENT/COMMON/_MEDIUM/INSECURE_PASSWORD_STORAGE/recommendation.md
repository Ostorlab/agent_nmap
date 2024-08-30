To safely store account credentials, consider the following recommendations:

- For Android, use `AccountManager` to store account credentials.
- For iOS, use `keychain` to store account credentials.

=== "Kotlin"
  ```kotlin
  import android.accounts.Account
  import android.accounts.AccountManager
  import android.content.Context
  
  fun saveCredentials(context: Context, accountType: String, username: String, password: String) {
      val accountManager = AccountManager.get(context)
      val account = Account(username, accountType)
      accountManager.addAccountExplicitly(account, password, null)
  }
  
  fun getCredentials(context: Context, accountType: String, username: String): String? {
      val accountManager = AccountManager.get(context)
      val accounts = accountManager.getAccountsByType(accountType)
      for (account in accounts) {
          if (account.name == username) {
              return accountManager.getPassword(account)
          }
      }
      return null
  }
  ```

=== "Swift"
  ```swift
  import Foundation

  func saveCredentials(username: String, password: String) {
      let query: [String: Any] = [
          kSecClass as String: kSecClassGenericPassword,
          kSecAttrAccount as String: username,
          kSecValueData as String: password.data(using: .utf8)!,
          kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked
      ]
      
      SecItemDelete(query as CFDictionary)
      SecItemAdd(query as CFDictionary, nil)
  }
  
  func getCredentials(username: String) -> String? {
      let query: [String: Any] = [
          kSecClass as String: kSecClassGenericPassword,
          kSecAttrAccount as String: username,
          kSecReturnData as String: true,
          kSecMatchLimit as String: kSecMatchLimitOne
      ]
      
      var dataTypeRef: AnyObject?
      let status = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)
      
      guard status == errSecSuccess, let data = dataTypeRef as? Data else {
          return nil
      }
      
      return String(data: data, encoding: .utf8)
  }
  ```

=== "Flutter"
  ```dart
  import 'package:flutter/services.dart';

  class CredentialService {
    static const platform = MethodChannel('credentialChannel');
  
    static Future<void> saveCredentials(String username, String password) async {
      try {
        await platform.invokeMethod('saveCredentials', {'username': username, 'password': password});
      } on PlatformException catch (e) {
        print("Failed to save credentials: '${e.message}'.");
      }
    }
  
    static Future<String?> getCredentials(String username) async {
      try {
        return await platform.invokeMethod('getCredentials', {'username': username});
      } on PlatformException catch (e) {
        print("Failed to get credentials: '${e.message}'.");
        return null;
      }
    }
  }
  ```