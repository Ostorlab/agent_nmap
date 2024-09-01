Avoiding memory leaks in applications is difficult. There are steps you can take to help detect and address memory leaks:

- **Use Profiling Tools:** Employ memory profiling tools like Android Profiler (for Android) or Instruments (for iOS) to identify memory leaks and memory usage patterns.
- **Use Leak Detection Libraries:** Integrate leak detection libraries like LeakCanary (for Android) or Instruments (for iOS) into your development process to automatically detect and pinpoint memory leaks during development and testing phases.
- **Use Sanitizers:** Consider building your application with sanitizers like `HWAddressSanitizer`, `GWP-ASan` and `Arm Memory Tagging Extension`  
