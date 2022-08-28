extern unsigned long lifter_addr_map[];
extern unsigned int lifter_addr_map_size;

int printf(const char *restrict format, ...);

unsigned long lifter_get_mapped_addr(unsigned long addr) {

    for (unsigned int i = 0; i < lifter_addr_map_size * 3; i+=3) {
        unsigned long region_addr = lifter_addr_map[i];
        unsigned long region_size = lifter_addr_map[i + 1];
        unsigned long target_addr = lifter_addr_map[i + 2];

        if (addr >= region_addr && addr <= (region_addr + region_size)) {
            return (addr - region_addr) + target_addr;
        }
    }

    // If we are here, the address could not be lifted.

    printf("Could not map address: 0x%lx\n", addr);

    return 0;
}