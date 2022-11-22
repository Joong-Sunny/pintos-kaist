/* Tests the halt system call. */

#include "tests/lib.h"
#include "tests/main.h"
#include <stdio.h>

void
test_main (void) 
{
  printf("===hi=== \n");
  halt ();
  fail ("should have halted");
}
