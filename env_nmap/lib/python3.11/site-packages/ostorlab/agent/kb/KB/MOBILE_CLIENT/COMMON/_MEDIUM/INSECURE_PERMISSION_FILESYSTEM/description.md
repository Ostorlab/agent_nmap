The application handles files using insecure permissions (world-readable or world-writable) or is targeting external
memory devices like SD card with weak permissions.

According to Android security designing idea, files are used only for making information persistence
and temporarily saved (cache), and it should be private in principle. Exchanging information between
applications should not be direct access to files, but it should be exchanged by an inter-application linkage
system, like Content Provider or Service. By using this, inter-application access control can be achieved.

### World readable permission

World readable may present a risk if they store sensitive information that may present a risk if accessed by an
unauthorized party, like bank account statement or session key storage file.

### World writable permission

World writable may present a risk if it is to perform sensitive actions, like URL list or session parameters.

### External storage

Accessing External storage in apps targeting Android 9 (API level 28) and lower using `getExternalFilesDir()` gives
other apps the right to read and change those files.

The method that apps access files in the external storage of devices running Android 10 (API level 29) or
higher has been changed. For apps targeting Android 10, a filtered view for displaying files in external storage is
provided by
default. Each app can save the app files in the app-specific directory and constantly has read-write
access permissions for created files, and so permission does not need to be declared.