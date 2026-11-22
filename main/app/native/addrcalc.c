/* addrcalc add <hex> <hex>  -> 输出 0x...（64 位无符号） */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc != 4 || strcmp(argv[1], "add") != 0) {
        fprintf(stderr, "usage: %s add <hex> <hex>\n", argv[0]);
        return 2;
    }
    uint64_t a = strtoull(argv[2], NULL, 0);
    uint64_t b = strtoull(argv[3], NULL, 0);
    printf("0x%llx\n", (unsigned long long)(a + b));
    return 0;
}
