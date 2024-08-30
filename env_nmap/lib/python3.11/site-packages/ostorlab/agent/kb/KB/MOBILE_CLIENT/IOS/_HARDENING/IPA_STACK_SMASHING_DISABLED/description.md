Stack Smashing Protection is an exploit mitigation that helps detect buffer overflows being exploited and abort
execution before malicious code is executed. This feature is implemented by selecting appropriate functions, storing a
canary at the function prologue, and checking the value at the epilogue