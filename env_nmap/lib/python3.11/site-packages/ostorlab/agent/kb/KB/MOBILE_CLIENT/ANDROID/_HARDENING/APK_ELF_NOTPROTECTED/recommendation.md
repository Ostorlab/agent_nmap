To ensure that the stack canary feature is enabled when compiling with GCC, you can specify one of the compiler options:

- For basic stack protection, use `-fstack-protector`.
- For stronger protection including functions with local arrays or references to local frame addresses, use `-fstack-protector-strong`.
- For comprehensive protection checking in every function, use `-fstack-protector-all`.