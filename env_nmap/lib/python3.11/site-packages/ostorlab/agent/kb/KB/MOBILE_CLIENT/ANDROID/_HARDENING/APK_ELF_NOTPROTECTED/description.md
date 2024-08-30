Compilers, Operating Systems and Processors provide a set of techniques to protect and mitigate the risk of memory corruption vulnerabilities like Buffer Overflow or memory exploitation techniques like ROP (Return-Oriented-Programming).

Native code can easily benefit from protections like:

* `RELRO`: RELRO is a memory protection technique to harden against memory corruption exploitation techniques. RELRO prevents GOT overwrite attacks.
* `ASLR`: ASLR is a memory protection technique to harden against memory corruption exploitation technique. ASLR randomizes the address space of binary to prevent controlled address jumps.
* `No eXecute`: Mark memory region as non-executable to harden against memory corruption exploitation technique.
* `Stack canary`: Add a canary to memory that gets overwritten in the case of a memory corruption. The canary is checked at runtime to prevent the exploitation of the memory corruption vulnerability.