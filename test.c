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
