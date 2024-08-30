When file sharing is enabled, `UIFileSharingEnabled` is set to `true`, and the entire Documents folder is used for file
sharing.

Files not intended for user access via the file sharing feature should be stored in another part of the application's
bundle. An attacker can use physical access to the iOS device to gain access to them by abusing the file sharing feature in the
application.
