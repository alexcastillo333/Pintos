#include "threads/interrupt.h"
#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
void sys_exit (struct intr_frame *f, void *p);

#endif /* userprog/syscall.h */
