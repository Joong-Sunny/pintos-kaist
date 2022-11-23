#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
void check_address(void *addr);
void halt (void);
int write (int fd, const void *buffer, unsigned size);
void exit (int status);

#endif /* userprog/syscall.h */
