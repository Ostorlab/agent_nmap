The application is shipped debug symbols and debug information such as debugging information, line numbers, and descriptive function or method names, which make it easier to reverse engineer.

It is noteworthy that most crash reporting tools support uploading symbols to perform stack trace symbolization and don't require symbols to be present in the application.

To verify that the native libraries are not shipped with debug symbols, use the following command:

```bash
readelf --debug-dump=info <library>
```