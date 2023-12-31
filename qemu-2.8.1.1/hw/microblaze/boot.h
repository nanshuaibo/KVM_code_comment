#ifndef MICROBLAZE_BOOT_H
#define MICROBLAZE_BOOT_H

#include "hw/hw.h"

void microblaze_load_kernel(MicroBlazeCPU *cpu, hwaddr ddr_base,
                            uint32_t ramsize,
                            const char *initrd_filename,
                            const char *dtb_filename,
                            void (*machine_cpu_reset)(MicroBlazeCPU *));

#endif /* MICROBLAZE_BOOT_H */
