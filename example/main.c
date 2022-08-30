extern unsigned long _main();
extern void __lifter_init();

int main() {
    __lifter_init();
    _main();

    return 0;
}