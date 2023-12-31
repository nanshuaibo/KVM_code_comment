/*
 * pcie_port.h
 *
 * Copyright (c) 2010 Isaku Yamahata <yamahata at valinux co jp>
 *                    VA Linux Systems Japan K.K.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef QEMU_PCIE_PORT_H
#define QEMU_PCIE_PORT_H

#include "hw/pci/pci_bridge.h"
#include "hw/pci/pci_bus.h"

#define TYPE_PCIE_PORT "pcie-port"
#define PCIE_PORT(obj) OBJECT_CHECK(PCIEPort, (obj), TYPE_PCIE_PORT)

struct PCIEPort {
    /*< private >*/
    PCIBridge   parent_obj;
    /*< public >*/

    /* pci express switch port */
    uint8_t     port;
};

void pcie_port_init_reg(PCIDevice *d);

#define TYPE_PCIE_SLOT "pcie-slot"
#define PCIE_SLOT(obj) OBJECT_CHECK(PCIESlot, (obj), TYPE_PCIE_SLOT)

struct PCIESlot {
    /*< private >*/
    PCIEPort    parent_obj;
    /*< public >*/

    /* pci express switch port with slot */
    uint8_t     chassis;
    uint16_t    slot;
    QLIST_ENTRY(PCIESlot) next;
};

void pcie_chassis_create(uint8_t chassis_number);
PCIESlot *pcie_chassis_find_slot(uint8_t chassis, uint16_t slot);
int pcie_chassis_add_slot(struct PCIESlot *slot);
void pcie_chassis_del_slot(PCIESlot *s);

#endif /* QEMU_PCIE_PORT_H */
