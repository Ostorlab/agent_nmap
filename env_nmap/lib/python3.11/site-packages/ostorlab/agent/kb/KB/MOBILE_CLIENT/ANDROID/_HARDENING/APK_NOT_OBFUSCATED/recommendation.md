Below are steps you can consider to make your application less prone to reverse engineering :

#### Obfuscate Java source code with Proguard.

To add Proguard to you application, add the following to the `build.gradle` file:

=== "Gradle"
	```gradle
    buildTypes {
            release {
                minifyEnabled true
                proguardFiles getDefaultProguardFile('proguard-android.txt'), 'proguard-rules.pro'
            }
        }
    ```



This tells Gradle to use ProGuard for code obfuscation in the release build. You can then create a "proguard-rules.pro"
file in the app's "app" directory to configure the obfuscation rules.

Example `proguard-rules.pro`:

```
# Keep the names of classes in this package
-keep class com.example.myapplication.** { *; }

# Keep all public and protected methods in these classes
-keepclassmembers class com.example.myapplication.** {
    public protected *;
}

# Keep all native method names
-keepclassmembers class * {
    native <methods>;
}

# Keep all fields with the specified name
-keepclassmembers class * {
    private int myField;
}

# Keep all classes that implement Parcelable
-keep class * implements android.os.Parcelable {
  public static final android.os.Parcelable$Creator *;
}

# Keep all Enum classes
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# Keep all annotations
-keepattributes *Annotation*

# Preserve all entry points (like main methods)
-keep public class * {
    public static void main(java.lang.String[]);
}

# Keep all Serializable classes
-keep class * implements java.io.Serializable {
    *;
}
```

#### Obfuscate Java source code with Dexguard.

To enable Dexguard in your application, you can add the following to the `build.gradle` file:

=== "Gradle"
	```gradle
    buildTypes {
            release {
                minifyEnabled true
                useProguard false
                proguardFiles getDefaultProguardFile('proguard-android.txt'), 'proguard-rules.pro'
                dexguard {
                    config 'dexguard-release.cfg'
                }
            }
        }
	```


This tells Gradle to use DexGuard for code obfuscation in the release build. You can create a"dexguard-project.txt" file in the app's "app" directory to configure the DexGuard project, and a"dexguard-release.cfg" file to configure the obfuscation for the release build.

By default, when you enable code obfuscation using DexGuard, it will use its own obfuscation rules in addition to any rules specified in the ProGuard configuration file. However, you can disable the use of ProGuard's rules by setting the `useProguard` option to false.

* Verification application signing certificate during runtime by checking `context.getPackageManager().signature`
* Check application installer to ensure it matches the Android Market by calling `context.getPackageManager().getInstallerPackageName`
* Check running environment at runtime

#### Check if the app is running on an emulator

You can add the following check to your application to detect if it's running on an emulator.

=== "Java"
	```java
    private static String getSystemProperty(String name) throws Exception {
        Class systemPropertyClazz = Class.forName("android.os.SystemProperties");
        return (String) systemPropertyClazz.getMethod("get", new Class[] { String.class }).invoke(systemPropertyClazz, new Object[] { name });
    }
    
    public static boolean checkEmulator() {
    
        try {
            boolean goldfish = getSystemProperty("ro.hardware").contains("goldfish");
            boolean qemu = getSystemProperty("ro.kernel.qemu").length() > 0;
            boolean sdk = getSystemProperty("ro.product.model").equals("sdk");
    
            if (qemu || goldfish || sdk) {
                return true;
            }
    
        } catch (Exception e) {}

        return false;
    }
	```



#### Check debug flag at runtime

Similarly, you can check if the application is in debug mode during runtime

=== "Java"
	```java
	    context.getApplicationInfo().applicationInfo.flags & ApplicationInfo.FLAG_DEBUGGABLE;
	```
