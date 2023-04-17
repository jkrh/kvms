#include <stddef.h>
#include <stdint.h>
#include "hvccall.h"
#include "helpers.h"

__attribute__((noreturn)) void exit(int v)
{
	panic("exit called with code %d\n", v);
	while (1)
		wfi();
}
