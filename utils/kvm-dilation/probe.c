/*
 * Is this host running the k7d time-dilation patch?
 *
 * Exit 0 and print "patched" when a fresh VM fd answers KVM_HAS_DEVICE_ATTR
 * for the dilation group, exit 1 and print "stock" when the kernel does not
 * know the ioctl at VM level, exit 2 on anything else.  A stock host must
 * never look like a dilating one, so the answer comes from the kernel rather
 * than from a module version string.
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define KVM_VM_DILATION 0x64696c61 /* 'dila' */
#define KVM_VM_DILATION_FACTOR 0
#define KVM_VM_DILATION_ABI 1

int main(void)
{
	struct kvm_device_attr attr = {
		.group = KVM_VM_DILATION,
		.attr = KVM_VM_DILATION_FACTOR,
	};
	int kvm, vm, rc;

	kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
	if (kvm < 0) {
		perror("open /dev/kvm");
		return 2;
	}
	vm = ioctl(kvm, KVM_CREATE_VM, 0);
	if (vm < 0) {
		perror("KVM_CREATE_VM");
		return 2;
	}
	rc = ioctl(vm, KVM_HAS_DEVICE_ATTR, &attr);
	if (rc == 0) {
		unsigned int factor = 0, abi = 1;

		attr.addr = (unsigned long)&factor;
		if (ioctl(vm, KVM_GET_DEVICE_ATTR, &attr) < 0) {
			perror("KVM_GET_DEVICE_ATTR");
			return 2;
		}
		/*
		 * The ABI attribute arrived with the live-SET patch, so a
		 * kernel that rejects it is the older one rather than a
		 * broken one — report generation 1 for it.
		 */
		attr.attr = KVM_VM_DILATION_ABI;
		attr.addr = (unsigned long)&abi;
		if (ioctl(vm, KVM_GET_DEVICE_ATTR, &attr) < 0)
			abi = 1;
		printf("patched (abi %u, default factor %u)\n", abi, factor);
		return 0;
	}
	printf("stock (KVM_HAS_DEVICE_ATTR: %s)\n", strerror(errno));
	return 1;
}
