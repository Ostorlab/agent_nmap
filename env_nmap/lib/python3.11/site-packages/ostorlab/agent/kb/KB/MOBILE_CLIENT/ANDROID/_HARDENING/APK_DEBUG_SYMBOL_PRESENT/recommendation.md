Remove all symbols and debug data from the application. 

To do so, here are some recommendations:

* Configure the build type to exclude debug information by compiling in release mode.

=== "build.gradle"
  ```gradle
    android {
        ...
        buildTypes {
            release {
                debuggable false
                ...
            }
        }
    }
  ```

* Use [ProGuard](https://www.guardsquare.com/en/products/proguard) to strip native debugging symbols.

=== "build.gradle"
	```gradle
    buildTypes {
            ...
            release {
                minifyEnabled true
                proguardFiles getDefaultProguardFile('proguard-android.txt'), 'proguard-rules.pro'
                ...
            }
        }
    ```

* Use the `strip` command to remove symbols from native libraries:

=== "Bash"
  ```bash
  strip -s <library>
  ```