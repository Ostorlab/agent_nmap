A memory leak is an unintentional form of memory consumption whereby the application fails to free an allocated block of
memory when no longer needed. The consequences of such an issue depend on the application itself.

Consider the following general three cases:

* Short Lived User*land Application: Little if any noticeable effect. Modern operating system recollects lost memory
* after program termination.
* Long Lived User*land Application:  Application Potentially dangerous. These applications continue to waste memory
* over time, eventually consuming all RAM resources. Leads to abnormal system behavior.
* Kernel*land Process: Very dangerous. Memory leaks in the kernel level lead to serious system stability issues. Kernel
* memory is very limited compared to user land memory and should be handled cautiously.

The following example is basic memory leak in `C`:

=== "C"
	```c
	#include <stdlib.h>
	#include <stdio.h>
	
	#define  LOOPS    10
	#define  MAXSIZE  256
	
	int main(int argc, char **argv)
	{
	     int count = 0;
	     char *pointer = NULL;
	
	     for(count=0; count<LOOPS; count++) {
	          pointer = (char *)malloc(sizeof(char) * MAXSIZE);
	     }
	
	     free(pointer);
	
	     return count;
	}
	```



In this example, we have 10 allocations of size MAXSIZE. Every allocation, except the last, is lost. If
no pointer is pointed to the allocated block, it is unrecoverable during program execution. A simple fix to this trivial
example is to place the free() call inside the ‘for’ loop.