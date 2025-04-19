🔍 SAST Tool for C

This is a lightweight static analysis tool built in Python to detect potential vulnerabilities in C code, including dangerous functions, arithmetic overflow/underflow patterns, and unused variables.

📦 Features
✅ Detects use of **dangerous C functions** like `gets()`, `strcpy()`, `scanf()`, etc.
✅ Identifies **integer arithmetic operations** that may cause overflow/underflow.
✅ Tracks **declared but unused variables**.
✅ CLI-based for easy automation and integration.

🚀 Usage

~bash
python3 main.py test.c

📥 Example Input 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main() {
    int a = 1000;
    int b = 2000;
    int result;

    // Integer overflow example
    result = a * b;

    // Dangerous function usage
    char buffer[10];
    gets(buffer);  // Unsafe
    strcpy(buffer, "Hello");  // Unsafe

    // Unused variable
    int unused_var;

    // System call (possible command injection)
    system("ls -la");

    return 0;
}
📤 Sample Output
Line 11: Potential integer overflow/underflow in arithmetic operation
    Code: result = a * b;

Line 15: Use of dangerous function 'gets'
    Code: gets(buffer);  // Unsafe

Line 16: Use of dangerous function 'strcpy'
    Code: strcpy(buffer, "Hello");  // Unsafe

Line 22: Use of dangerous function 'system'
    Code: system("ls -la");

Line 19: Variable 'unused_var' declared but not used
    Code: Declaration of unused_var

Line 5: Variable 'main' declared but not used
    Code: Declaration of main
