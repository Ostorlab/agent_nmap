The application exposes a file provider using `androidx.core.content.FileProvider`. The provider specifies available files in the metadata child attribute with the name `android.support.FILE_PROVIDER_PATHS`.

The attribute is required to generate URI for directories specified `android.support.FILE_PROVIDER_PATHS` configuration file.

Android defines multiple paths types:

```xml

<root-path name="name" path="path"/>
```

* Checking the documentation of the [FileProvider](https://developer.android.com/reference/androidx/core/content/FileProvider) , you will not find the `<root-path...>` among the available paths.
This path although not documented is available and can be used to provide access to internal storage of the app along with `/data` and `sdcard`.
This path grants access to protected parts of the app and of the device and thus exposes the application filesystem.

```xml

<files-path name="name" path="path"/>
```

* Represent files in the files/ subdirectory of your app's internal storage area. This subdirectory is the same as the value returned by `Context.getFilesDir()`.

```xml

<cache-path name="name" path="path"/>
```

* Represent files in the cache subdirectory of your app's internal storage area. The root path of this subdirectory is the same as the value returned by `getCacheDir()`.

```xml

<external-path name="name" path="path"/>
```

* Represent files in the root of the external storage area. The root path of this subdirectory is the same as the value returned by `Environment.getExternalStorageDirectory()`.

```xml

<external-files-path name="name" path="path"/>
```

* Represent files in the root of your app's external storage area. The root path of this subdirectory is the same as the value returned by `Context.getExternalFilesDir(null)`.

```xml

<external-cache-path name="name" path="path"/>
```

* files in the root of your app's external cache area. The root path of this subdirectory is the same as the value returned by `Context.getExternalCacheDir()`.

```xml

<external-media-path name="name" path="path"/>
```

* Represent files in the root of your app's external media area. The root path of this subdirectory is the same as the value returned by the first result of `Context.getExternalMediaDirs()`.

In the example below , we observe the provider has the root folder configuration that allows us to access home directory (which also includes /data and /sdcard directory).
```xml
<?xml version="1.0" encoding="utf-8"?>
<paths xmlns:android="http://schemas.android.com/apk/res/android">
    <root-path name="root" path="/"/>
</paths>
```
This misconfiguration can be chained with other vulnerabilities like `Intent Redirection` to steal sensitive data or `Remote Code Execution` by overwriting native libraries.
