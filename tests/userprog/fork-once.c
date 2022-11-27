/* Forks and waits for a single child process. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void
test_main (void) 
{
  int pid;

  pid = fork("child");
  msg ("forked!!!...");

  if (pid){
    msg ("pid is... %d",pid);
    int status = wait (pid);
    msg ("Parent: child exit status is %d", status);
  } else {
    msg ("child run");
    exit(81);
  }


  // if ((pid = fork("child"))){
  //   msg ("waiting...");
  //   msg ("pid is... %d",pid);
  //   int status = wait (pid);
  //   msg ("Parent: child exit status is %d", status);
  // } else {
  //   msg ("child run");
  //   exit(81);
  // }
}
