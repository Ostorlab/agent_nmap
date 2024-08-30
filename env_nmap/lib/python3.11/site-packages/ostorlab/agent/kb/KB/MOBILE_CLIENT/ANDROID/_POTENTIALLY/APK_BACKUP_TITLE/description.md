Backup mode is a feature in Android that allows users to backup and restore data and settings from one device to
another. By default, Android performs a full backup of applications including the private files stored on `/data`
partition. When backup mode is enabled on an Android device, the __Backup Manager Service__ will periodically upload
data and settings to the user's Google Drive account, such as app data, Wi-Fi passwords, and other settings. This data
can then be restored to the same device, or a different device if the user signs in to the same Google account.

Here are some key features of the Backup Manager Service in Android:

1. _Automatic backup_: The Backup Manager Service automatically backs up app data at regular intervals, typically once a
   day. It can also trigger backups when specific events occur, such as when a device is connected to a power source or
   when the user manually initiates a backup.

2. _Incremental backups_: The Backup Manager Service performs incremental backups, meaning it only backs up data that has
   changed since the last backup. This helps reduce the backup size and speed up the backup process.

3. _Encrypted backups_: Backups created by the Backup Manager Service are encrypted with a key unique to each user's
   device, ensuring that only the user or someone with their Google account credentials can access the backup data.

4. _App-specific backups_: The Backup Manager Service allows apps to specify which data should be backed up and which
   data should be excluded from backups. This can help reduce the size of backups and ensure that sensitive data is
   not included.

5. _Restore functionality_: The Backup Manager Service also provides a restore functionality that allows users to restore
   their app data to a new or factory-reset device, or to restore data to an existing device after an app has been
   uninstalled and reinstalled.