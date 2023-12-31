#include "io.h"

int main(void)
{
    long long rd, rs, rt;
    long long result;

    rs     = 0x11777066;
    rt     = 0x55AA70FF;
    result = 0x0F;
    __asm
        ("cmpgu.le.qb %0, %1, %2\n\t"
         : "=r"(rd)
         : "r"(rs), "r"(rt)
        );
    if (rd != result) {
        printf("cmpgu.le.qb wrong\n");

        return -1;
    }

    rs     = 0x11777066;
    rt     = 0x11766066;
    result = 0x09;
    __asm
        ("cmpgu.le.qb %0, %1, %2\n\t"
         : "=r"(rd)
         : "r"(rs), "r"(rt)
        );
    if (rd != result) {
        printf("cmpgu.le.qb wrong\n");

        return -1;
    }

    return 0;
}
