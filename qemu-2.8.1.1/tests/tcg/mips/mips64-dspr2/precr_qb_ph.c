#include"io.h"

int main()
{
    long long rd, rs, rt;
    long long result;

    rs = 0x12345678;
    rt = 0x87654321;
    result = 0x34786521;

    __asm
        ("precr.qb.ph %0, %1, %2\n\t"
         : "=r"(rd)
         : "r"(rs), "r"(rt)
        );
    if (result != rd) {
        printf("precr.qb.ph error\n");
        return -1;
    }

    return 0;
}
