The application should provide as little explanatory information as possible with the compiled code. Metadata such as
debugging information, line numbers, and descriptive function or method names make the binary or byte-code
easier to reverse engineer.

These symbols can be saved in "Stabs" format, the DWARF format, or in .symbols r .symbolsmap files. It is noteworthy
that most crash reporting tools support uploading symbols to perform stack trace symbolization and don't require
symbols to be present in the application. 
