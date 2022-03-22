#include <stdlib.h>
#include <stdio.h>
#define SIZE 0x100

void main(){
	char *str1 = "please give a first input that is safely handled :\0";
	printf("%s\n", str1);

	char safe_string[SIZE];
	fgets(safe_string, SIZE, stdin);
	printf("%s\n", safe_string);

	char *str2 = "please give a second input that is not safely handled :\0";
	printf("%s\n", str2);

	char vuln_string[SIZE];
	fgets(vuln_string, SIZE, stdin);

	char *str3 = "meanwhile, this integer is printed with printf :\0";
	int integer = 12345;
	int *stack_pointer = &integer;
	printf("%s %d\n", str3, *stack_pointer);

	printf(vuln_string);
}
