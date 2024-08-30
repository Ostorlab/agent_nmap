Obfuscation refers to methods to obscure code and make it hard to understand. Compiled Java classes can be decompiled if there is no obfuscation during compilation step. It works by modifying the code and metadata of the app in a way that makes it difficult for attackers to understand the code and modify it to introduce vulnerabilities or add malicious functionality. Obfuscators typically achieve this by renaming classes, methods, and variables to non-meaningful names, removing debugging information, and adding bogus code to confuse decompilers.

Adversaries can steal code and sensitive information, introduce vulnerabilities that can compromise the app's security, or repurpose and sell the code in a new application or create a malicious fake application based on the initial one.
If this code is not obfuscated, it can be easily decompiled using tools like Apktool or JADX.

Code obfuscation only slows the attacker from reverse engineering but does not make it impossible.