#include <stdio.h>
#include <sys/ioctl.h>
#include "../../src/bpf/include/ioctl.h"

int main(int argc, char *argv[])
{
	printf("ioctl op is %x\n", BPFCONTAIN_OP_CONFINE);

	bpfcontain_ioctl_t args = {};
	args.confine.policy_id = 1337;
	int ret = ioctl(0, BPFCONTAIN_OP_CONFINE, &args);
	printf("good call return value: %d\n", ret);

	ret = ioctl(0, BPFCONTAIN_OP_CONFINE + 1, &args);
	printf("bad call return value: %d\n", ret);

	return 0;
}
