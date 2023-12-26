/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __KVM_IODEV_H__
#define __KVM_IODEV_H__

#include <linux/kvm_types.h>
#include <linux/errno.h>

struct kvm_io_device;
struct kvm_vcpu;

/**
 * struct kvm_io_device_ops 定义了一组函数指针，用于处理 I/O 操作。这些函数在 kvm slots_lock 的保护下被调用。
 *
 * - 如果读取和写入处理程序返回 0，表示当前设备已处理事务；否则，返回非零值，将事务传递给下一个设备。
 *
 * - destructor 是一个函数指针，用于在设备被销毁时进行清理操作。当设备不再需要时，调用此函数来释放资源。
 */
struct kvm_io_device_ops {
    /**
     * read 函数指针负责处理 I/O 读取操作。它接受以下参数：
     *
     * @param vcpu   指向与 I/O 操作相关联的虚拟 CPU 结构的指针。
     * @param this   指向表示当前 I/O 设备的 kvm_io_device 结构的指针。
     * @param addr   虚拟地址，表示 I/O 操作的地址。
     * @param len    读取的字节数。
     * @param val    存储读取结果的缓冲区的指针。
     *
     * 如果 I/O 操作在当前设备中被处理，函数应返回0；否则，返回非零值，将操作传递给下一个设备。
     */
    int (*read)(struct kvm_vcpu *vcpu,
                struct kvm_io_device *this,
                gpa_t addr,
                int len,
                void *val);

    /**
     * write 函数指针负责处理 I/O 写入操作。它接受以下参数：
     *
     * @param vcpu   指向与 I/O 操作相关联的虚拟 CPU 结构的指针。
     * @param this   指向表示当前 I/O 设备的 kvm_io_device 结构的指针。
     * @param addr   虚拟地址，表示 I/O 操作的地址。
     * @param len    写入的字节数。
     * @param val    包含写入数据的缓冲区的指针。
     *
     * 如果 I/O 操作在当前设备中被处理，函数应返回0；否则，返回非零值，将操作传递给下一个设备。
     */
    int (*write)(struct kvm_vcpu *vcpu,
                 struct kvm_io_device *this,
                 gpa_t addr,
                 int len,
                 const void *val);

    /**
     * destructor 是一个函数指针，用于在设备被销毁时执行清理操作。当设备不再需要时调用此函数。
     */
    void (*destructor)(struct kvm_io_device *this);
};



struct kvm_io_device {
	const struct kvm_io_device_ops *ops;
};

static inline void kvm_iodevice_init(struct kvm_io_device *dev,
				     const struct kvm_io_device_ops *ops)
{
	dev->ops = ops;
}

static inline int kvm_iodevice_read(struct kvm_vcpu *vcpu,
				    struct kvm_io_device *dev, gpa_t addr,
				    int l, void *v)
{
	return dev->ops->read ? dev->ops->read(vcpu, dev, addr, l, v)
				: -EOPNOTSUPP;
}

static inline int kvm_iodevice_write(struct kvm_vcpu *vcpu,
				     struct kvm_io_device *dev, gpa_t addr,
				     int l, const void *v)
{
	return dev->ops->write ? dev->ops->write(vcpu, dev, addr, l, v)
				 : -EOPNOTSUPP;
}

static inline void kvm_iodevice_destructor(struct kvm_io_device *dev)
{
	if (dev->ops->destructor)
		dev->ops->destructor(dev);
}

#endif /* __KVM_IODEV_H__ */
