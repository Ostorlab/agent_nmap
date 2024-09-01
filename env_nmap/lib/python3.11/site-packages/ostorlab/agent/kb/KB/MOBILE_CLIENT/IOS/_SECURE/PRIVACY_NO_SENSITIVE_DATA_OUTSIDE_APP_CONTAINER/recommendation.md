### iOS

On iOS, developers can leverage the iOS Data Protection API to protect sensitive data. The API relies on
the `Secure Enclave Processor` (SEP) to provide secure cryptographic processing and key management.

Files can be assigned a protection class that offers different levels of protection:

* __Complete Protection__ (`NSFileProtectionComplete`): A key derived from the user passcode and the device UID protects
  this class key. The derived key is wiped from memory shortly after the device is locked, making the data inaccessible
  until the user unlocks the device.

* __Protected Unless Open__ (`NSFileProtectionCompleteUnlessOpen`): This protection class is similar to Complete
  Protection, but if the file is opened when unlocked, the app can continue to access the file even if the user locks
  the device. This protection class is used when, for example, a mail attachment is downloading in the background.

* __Protected Until First User Authentication__ (`NSFileProtectionCompleteUntilFirstUserAuthentication`): The file can
  be accessed as soon as the user unlocks the device for the first time after booting. It can be accessed even if the
  user subsequently locks the device and the class key is not removed from memory.

* __No Protection__ (`NSFileProtectionNone`): The key for this protection class is protected with the UID only. The
  class key is stored in "Effaceable Storage", which is a region of flash memory on the iOS device that allows the
  storage of small amounts of data. This protection class exists for fast remote wiping (immediate deletion of the class
  key, which makes the data inaccessible).

All class keys except `NSFileProtectionNone` are encrypted with a key derived from the device UID and the user's
passcode.
As a result, decryption can happen only on the device itself and requires the correct passcode.

Since iOS 7, the default data protection class is "Protected Until First User Authentication".

The Keychain can also store small data bits, like encryption keys and session tokens. Access to the keychain is done
using a custom API like:

* `SecItemAdd`
* `SecItemUpdate`
* `SecItemCopyMatching`
* `SecItemDelete`

Data stored in the Keychain is protected via a class structure similar to the class structure used for file encryption.
Items added to the Keychain are encoded as a binary plist and encrypted with a 128-bit AES per-item key in
Galois/Counter Mode (GCM). Note that larger blobs of data aren't meant to be saved directly in the Keychain-that's the
purpose of the Data Protection API. You can configure data protection for Keychain items by setting
the `kSecAttrAccessible` key in the call to `SecItemAdd` or `SecItemUpdate`.
The following
configurable [accessibility values for kSecAttrAccessible](https://developer.apple.com/documentation/security/keychain_services/keychain_items/item_attribute_keys_and_values#1679100 "Accessibility Values for kSecAttrAccessible")
are the Keychain Data Protection classes:

- `kSecAttrAccessibleAlways`: The data in the Keychain item can always be accessed, regardless of whether the device is
  locked.
- `kSecAttrAccessibleAlwaysThisDeviceOnly`: The data in the Keychain item can always be accessed, regardless of whether
  the device is locked. The data won't be included in an iCloud or local backup.
- `kSecAttrAccessibleAfterFirstUnlock`: The data in the Keychain item can't be accessed after a restart until the user
  has unlocked the device.
- `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`: The data in the Keychain item can't be accessed after a restart
  until the device has been unlocked once by the user. Items with this attribute do not migrate to a new device. Thus,
  these items will not be present after restoring from a backup of a different device.
- `kSecAttrAccessibleWhenUnlocked`: The data in the Keychain item can be accessed only while the user unlocks the
  device.
- `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`: The data in the Keychain item can be accessed only while the user
  unlocks the device. The data won't be included in an iCloud or local backup.
- `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`: The data in the Keychain can be accessed only when the device is
  unlocked. This protection class is only available if a passcode is set on the device. The data won't be included in an
  iCloud or local backup.

`AccessControlFlags` define the mechanisms with which users can authenticate the key (`SecAccessControlCreateFlags`):

- `kSecAccessControlDevicePasscode`: Access the item via a passcode.
- `kSecAccessControlBiometryAny`: Access the item via one of the fingerprints registered to Touch ID. Adding or removing
  a fingerprint won't invalidate the item.
- `kSecAccessControlBiometryCurrentSet`: Access the item via one of the fingerprints registered to Touch ID. Adding or
  removing a fingerprint _will_ invalidate the item.
- `kSecAccessControlUserPresence`: Access the item via either one of the registered fingerprints (using Touch ID) or
  default to the passcode.

### Android

On Android, developers can leverage several capabilities to store data, like Shared Preferences, SQLite, Internal and
External Storage but can also leak data through a mechanism like logging, backup, cache ...

Shared Preference is a commonly used API for data storage that can be declared with world-readable permissions. Insecure
use of the Shared Preferences API can expose data.

SQLite is another common form to store data and is unencrypted. Developers must prefer encrypted alternatives like
SQLCipher that offer improved data privacy.

Internal storage is containerized by default and cannot be accessed by other applications on the device. It is however
possible to set insecure modes `MODE_WORLD_READABLE` and `MODE_WORLD_WRITEABLE`, which are both deprecated.

External storage is world readable and must not be used to store sensitive data. It is important to note that data
stored out the application container `/data/data/<package-name>` will not delete when the application is removed.

Android KeyStore and KeyChain provide secure data storage. KeyStore uses a public key to create an encryption secret to
encrypt data. KeyChain is used to store system-wide private keys and will require the user to set a pin or password.
