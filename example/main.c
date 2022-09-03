#include <sys/mman.h>
#include <stdio.h>

extern unsigned long _main();
extern void __lifter_init();

unsigned long stack;

int main() {
    stack = (unsigned long) mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    printf("stack: 0x%lx\n", stack);

    __lifter_init();
    _main();

    return 0;
}