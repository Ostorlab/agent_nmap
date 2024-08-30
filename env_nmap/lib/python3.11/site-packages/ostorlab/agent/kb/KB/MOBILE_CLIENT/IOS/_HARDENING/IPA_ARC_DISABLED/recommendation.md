To enable ARC for the entire project:

1. Open Xcode project.
2. Go to project settings.
3. Select target.
4. Navigate to "Build Settings" tab.
5. Search for "Objective-C Automatic Reference Counting".
6. Set "Objective-C Automatic Reference Counting" to "YES".

Alternatively, enable ARC for specific files:

1. Locate file(s) where ARC should be enabled.
2. Select file(s) in project navigator.
3. Go to "File Inspector" on the right.
4. Find "Compiler Flags" section.
5. Add `-fobjc-arc` to compiler flags.
6. Save changes.
