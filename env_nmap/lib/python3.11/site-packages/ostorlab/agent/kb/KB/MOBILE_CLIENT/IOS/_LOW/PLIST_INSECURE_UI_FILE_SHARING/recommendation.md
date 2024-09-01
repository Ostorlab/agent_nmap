To ensure sensitive files are not leaked through file sharing:

- Make sure files containing sensitive information are not copied to the Documents directory. 
- If your app does not need this functionality, set the `UIFileSharingEnabled` flag in the `Info.plist` file to `false` or delete the option.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <!-- Other keys and values in your Info.plist file -->

    <key>UIFileSharingEnabled</key>
    <false/>

    <!-- Other keys and values in your Info.plist file -->
</dict>
</plist>
```