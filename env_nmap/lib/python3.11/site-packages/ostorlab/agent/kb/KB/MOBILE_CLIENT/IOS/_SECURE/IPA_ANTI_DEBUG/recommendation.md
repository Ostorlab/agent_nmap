To implement anti-debugging techniques, use several of these techniques:

`ptrace`: Use the `ptrace` system call with the `PT_DENY_ATTACH` flag to
prevent debuggers from attaching to the process. The system call is not
part of iOS public API and requires using the `dlsym` function to obtain
a function pointer to call it.

=== "C"
	```c
	#import <dlfcn.h>
	#import <sys/types.h>
	#import <stdio.h>
	typedef int (*ptrace_ptr_t)(int _request, pid_t _pid, caddr_t _addr, int _data);
	void anti_debug() {
	  ptrace_ptr_t ptrace_ptr = (ptrace_ptr_t)dlsym(RTLD_SELF, "ptrace");
	  ptrace_ptr(31, 0, 0, 0); // PTRACE_DENY_ATTACH = 31
	}
	```


`sysctl`: The function can be used to retrieve information about the
current process, including determining if the application is being
debugged.

=== "C"
	```c
	#include <assert.h>
	#include <stdbool.h>
	#include <sys/types.h>
	#include <unistd.h>
	#include <sys/sysctl.h>
	
	static bool AmIBeingDebugged(void)
	    // Returns true if the current process is being debugged (either
	    // running under the debugger or has a debugger attached post facto).
	{
	    int                 junk;
	    int                 mib[4];
	    struct kinfo_proc   info;
	    size_t              size;
	
	    // Initialize the flags so that, if sysctl fails for some bizarre
	    // reason, we get a predictable result.
	
	    info.kp_proc.p_flag = 0;
	
	    // Initialize mib, which tells sysctl the info we want, in this case
	    // we're looking for information about a specific process ID.
	
	    mib[0] = CTL_KERN;
	    mib[1] = KERN_PROC;
	    mib[2] = KERN_PROC_PID;
	    mib[3] = getpid();
	
	    // Call sysctl.
	
	    size = sizeof(info);
	    junk = sysctl(mib, sizeof(mib) / sizeof(*mib), &info, &size, NULL, 0);
	    assert(junk == 0);
	
	    // We're being debugged if the P_TRACED flag is set.
	
	    return ( (info.kp_proc.p_flag & P_TRACED) != 0 );
	}
	   
	```



`getppid`: iOS application can check the parent `PID` to detect if the
application has been started with a debugger.
