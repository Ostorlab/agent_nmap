Dependency confusion or substitution attack is a new attack technique that can lead to remote code execution. The attack typically affects build environments, CI/CD pipelines and developer workstation.

In most programming languages, external package management systems are available to fetch 3rd party dependencies.

Package managers usually offer the possibility to deploy private repositories to host internal-only packages.

During the build process, the package manager does not prioritize the private repositories, but the ones with the highest version. This behavior can be leveraged by an attacker by creating a malicious package on the public repository and using a high enough version to ensure the malicious package is the one used during build time.
