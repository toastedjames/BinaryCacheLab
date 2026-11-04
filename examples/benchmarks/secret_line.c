#include "fixture.h"
_Alignas(64) static volatile uint32_t values[32] = {[0]=7, [16]=7};
__attribute__((noinline)) static uint32_t lookup(unsigned secret) { return values[secret*16u]; }
int main(int argc, char **argv) { int s=read_secret(argc,argv); if(s<0)return 2; printf("%u\n",lookup((unsigned)s)); return 0; }
