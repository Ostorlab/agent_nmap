If you use DexClassLoader to load and execute additional DEX code:

* Do NOT use a world-writable directory (such as the SD card) for the dexPath
* Do NOT use a world-writable directory (such as the SD card) for the ODEX (optimized DEX which is the second paramter of the DexClassLoader constructor)

If you use PathClassLoader to load and execute additional jar/resources:

* Do NOT use a world-writable directory (such as the SD card) for the path
* Do NOT use a world-writable directory (such as the SD card) for the libpath. By default, the external storage is mounted with the noexec flag to prevent the execution of any native binaries on the mounted file system.