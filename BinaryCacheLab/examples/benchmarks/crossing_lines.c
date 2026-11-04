#include "fixture.h"
_Alignas(64) static volatile unsigned char bytes[128] = {
    [56]=7,[57]=7,[58]=7,[59]=7,[60]=7,[61]=7,[62]=7,[63]=7,[64]=7,[65]=7,[66]=7,[67]=7
};
__attribute__((noinline)) static unsigned lookup(unsigned secret) {
    unsigned sum=0,offset=secret?60u:56u;
    for(unsigned i=0;i<8;i++)sum+=bytes[offset+i];
    return sum;
}
int main(int argc, char **argv) { int s=read_secret(argc,argv); if(s<0)return 2; printf("%u\n",lookup((unsigned)s)); return 0; }
