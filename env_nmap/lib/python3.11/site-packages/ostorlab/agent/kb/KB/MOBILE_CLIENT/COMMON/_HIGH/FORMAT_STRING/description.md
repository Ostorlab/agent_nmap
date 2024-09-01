Format string vulnerability occurs when a program does not properly validate or sanitize user input that is used as a format specifier in a formatted output function. This can allow an attacker to manipulate the format string argument and potentially execute arbitrary code or disclose sensitive information.

The impact of format string vulnerabilities can be significant, leading to:
1. Information Disclosure: Exploiting a format string vulnerability enables an attacker to extract sensitive information from memory. This may include confidential data like passwords, encryption keys, or other critical information.

2. Remote Code Execution: Format string vulnerabilities can be exploited to execute arbitrary code on a system remotely. This allows attackers to gain control over the system, potentially leading to unauthorized access or the theft of sensitive data.

3. Denial of Service (DoS): A format string vulnerability can be manipulated by an attacker to crash the program or induce it into an infinite loop. This type of attack results in a denial of service (DoS), rendering the system or application inaccessible to legitimate users.

### Examples

=== "C"
  ```c
  // gcc vulnerable.c
  
  #include <stdio.h>
  #include <unistd.h>
  
  int main() {
      int secret_num = 0x8badf00d;
  
      char name[64] = {0};
      read(0, name, 64);
      printf("Hello ");
      printf(name);
      printf("! You'll never get my secret!\n");
      return 0;
  }
  ```
  