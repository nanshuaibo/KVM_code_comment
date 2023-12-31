#include "io.h"

int main(void)
{
    long long rd, rt, result;
    rt = 0x123456789ABCDEF0;
    result = 0x00120056009A00DE;

    __asm
        ("preceu.qh.obla %0, %1\n\t"
         : "=r"(rd)
         : "r"(rt)
        );

    if (result != rd) {
        printf("preceu.qh.obla error\n");

        return -1;
    }

    return 0;
}
