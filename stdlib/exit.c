#include <stddef.h>
#include <stdint.h>
#include "hvccall.h"

void exit(int v)
{
	panic("exit called with code %d\n", v);
}
