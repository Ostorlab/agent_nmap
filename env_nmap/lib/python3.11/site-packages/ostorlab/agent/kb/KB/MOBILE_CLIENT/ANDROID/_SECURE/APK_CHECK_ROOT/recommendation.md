Root detection on Android can be done using the `RootBeer` library, can use to a certain extent the **SafetyNet**
API to ensure the device profile is known and approved or can perform manual checks like:

* File presence of common Rooted files like `/sbin/su` or `/system/app/Superuser.apk`
* Check `su` is in the `PATH`
* Check for `supersu` in the running processes
* Check installed application against a list of known root apps like `eu.chainfire.supersu`
* Check for writable partitions and system directories

iOS can apply the same concept to check for Jailbreak presence:

* File presence of common Jailbreak files like `/Applications/Cydia.app`
* File permissions writing to locations outside the application sandbox
* Protocol handlers added by Cydia


