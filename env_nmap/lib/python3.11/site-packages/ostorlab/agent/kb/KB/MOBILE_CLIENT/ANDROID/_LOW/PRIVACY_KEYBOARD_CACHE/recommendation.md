Input fields that are expected to have sensitive information as input should use input types such as "textNoSuggestions" or "textPassword" to ensure the input does not get stored in the keyboard cache.

=== "XML"
  ```xml
  <?xml version="1.0" encoding="utf-8"?>
  <LinearLayout
      xmlns:android="http://schemas.android.com/apk/res/android"
      xmlns:app="http://schemas.android.com/apk/res-auto">
  
      <!-- This password field uses the `textPassword` input type to ensure that the input is not saved to the keyboard cache. -->
      <EditText
          android:id="@+id/password"
          android:inputType="textPassword"/>  
  </LinearLayout>
  ```

