# Default configuration for sparc64-softmmu

include pci.mak
include usb.mak
CONFIG_M48T59=y
CONFIG_PTIMER=y
CONFIG_SERIAL=y
CONFIG_PARALLEL=y
CONFIG_PCKBD=y
CONFIG_FDC=y
CONFIG_IDE_ISA=y
CONFIG_IDE_CMD646=y
CONFIG_PCI_APB=y
CONFIG_MC146818RTC=y
CONFIG_ISA_TESTDEV=y
