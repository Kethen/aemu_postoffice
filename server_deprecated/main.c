#include <stdio.h>
#include <stdbool.h>
#include "postoffice.h"

int main()
{
	bool stop_thread = false;
	start_postoffice(27313, 1000, 1000, &stop_thread);
}
