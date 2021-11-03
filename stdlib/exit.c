#include <stddef.h>
#include <stdint.h>
#include "hvccall.h"

void exit(int v)
{
	HYP_ABORT();
}
