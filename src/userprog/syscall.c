#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
static void syscall_handler (struct intr_frame *);
extern struct lock filesys_lock;
extern int ptrsize;

static bool bad_mem_access (void *uaddr)
{
  return (uaddr == NULL || is_kernel_vaddr (uaddr + 3) || 
          pagedir_get_page (thread_current ()->pagedir, uaddr) == NULL ||
          pagedir_get_page (thread_current ()->pagedir, uaddr + 3) == NULL);
}

void sys_exit (struct intr_frame *f, void *p)
{
  int status;
  if (p == NULL || bad_mem_access (f->esp + ptrsize))
    status = -1;
  else
    status = *(int *) (f->esp + ptrsize);
  
  f->eax = status;
  struct thread *cur = thread_current ();
  cur->exitstatus = status;
  sema_down (&cur->processexit);
  struct thread *parent = cur->parent;
  thread_exit();
}
/*Runs the executable whose name is given in cmd_line, passing any given arguments, and returns the new process's program id (pid). Must return pid -1, which otherwise should not be a valid pid, if the program cannot load or run for any reason. Thus, the parent process cannot return from the exec until it knows whether the child process successfully loaded its executable. You must use appropriate synchronization to ensure this.*/
static int sys_exec(struct intr_frame *f)
{
  void *arg1 = f->esp + ptrsize;
  if (bad_mem_access (arg1) || bad_mem_access ((void *) *(uintptr_t *) arg1))
    sys_exit (f, NULL);
  
  const char *cmd_line = (const char *) *(uintptr_t *) arg1;
  struct thread *t = thread_current ();
  int pid = process_execute (cmd_line);
  if (pid == TID_ERROR)
    return -1;
  pid = (t->childloadstatus == -1) ? -1 : pid;
  t->childloadstatus = 0;
  return pid;
}

static int sys_wait(struct intr_frame *f)
{
  if (bad_mem_access (f->esp + ptrsize))
    sys_exit (f, NULL);
  int pid = *(int *) (f->esp + ptrsize);
  return process_wait (pid);
}

static bool sys_create (struct intr_frame *f)
{
  void *arg1 = f->esp + ptrsize;
  if (bad_mem_access (arg1 + ptrsize) || 
      bad_mem_access ((void *) *(uintptr_t *) arg1))
    sys_exit (f, NULL);
  const char *file = (const char *) *(uintptr_t *) arg1;
  unsigned initial_size = *(unsigned *) (arg1 + ptrsize);
  lock_acquire (&filesys_lock);
  bool ret = filesys_create (file, initial_size);
  lock_release (&filesys_lock);
  return ret;
}

static bool sys_remove (struct intr_frame *f) {
  if (bad_mem_access (f->esp + ptrsize) || 
      bad_mem_access ((void *) *(uintptr_t *) (f->esp + ptrsize)))
    sys_exit (f, NULL);  
  const char *file = (const char *) *(uintptr_t *) (f->esp + ptrsize);
  lock_acquire (&filesys_lock);
  bool ret = filesys_remove (file);
  lock_release (&filesys_lock);
  return ret;
}

static int sys_open (struct intr_frame *f)
{
  void *arg1 = (f->esp + ptrsize);
  if (bad_mem_access (arg1) || bad_mem_access ((void *) *(uintptr_t *) arg1))
    sys_exit (f, NULL);
  const char *file_name = (const char *) *(uintptr_t *) arg1;
  struct thread *t = thread_current ();
  lock_acquire (&filesys_lock);
  struct file* file = filesys_open (file_name);
  lock_release (&filesys_lock);
  if (file == NULL)
    return -1;
  *(uintptr_t *) (t->open_files + t->file_descriptor) = (uintptr_t) file;
  return 2 + t->file_descriptor++;
}

static int sys_filesize (struct intr_frame *f)
{
  if (bad_mem_access (f->esp + ptrsize))
    sys_exit (f, NULL);
  int fd = *(int *) (f->esp + ptrsize);
  struct thread *t = thread_current ();
  struct file* file = (struct file *) *(uintptr_t *) (t->open_files + fd - 2);
  lock_acquire (&filesys_lock);
  int ret = (file == NULL) ? 0 : file_length (file);
  lock_release (&filesys_lock);
  return ret;
}

static int sys_read (struct intr_frame *f)
{
  void *arg1 = f->esp + ptrsize;
  if (bad_mem_access (arg1 + ptrsize * 2) || 
      bad_mem_access ((void *) *(uintptr_t *) (arg1 + ptrsize)))
      sys_exit(f, NULL);
  struct thread *t = thread_current ();
  int fd = *(int *) arg1;
  void *buffer = (void *) *(uintptr_t *) (arg1 + ptrsize);
  unsigned size = *(unsigned *) (arg1 + ptrsize * 2);
  
  if (fd == 1 || t->file_descriptor <= fd - 2)
    sys_exit (f, NULL);
  else if (fd == 0) 
  {
    input_getc();
    size = 1;
  } 
  else 
  {
    struct file* file = (struct file *) *(uintptr_t *) (t->open_files + fd - 2);
    lock_acquire (&filesys_lock);
    size = (file == NULL) ? -1 : file_read (file, buffer, size);
    lock_release (&filesys_lock);
  }
  return size;
}

static int sys_write (struct intr_frame *f)
{  
  void *arg1 = f->esp + ptrsize;
  if (bad_mem_access (arg1 + ptrsize * 2) || 
    bad_mem_access ((void *) *(uintptr_t *) (arg1 + ptrsize)))
    sys_exit(f, NULL);
  int fd = *(int *) arg1;
  void *buffer = (const void *) *(uintptr_t *) (arg1 + ptrsize);
  unsigned size = *(unsigned *) (arg1 + ptrsize * 2);
  struct thread *t = thread_current ();
  if (fd == 1) 
    putbuf (buffer, size);
  else if (fd == 0 || t->file_descriptor <= fd - 2)
    sys_exit (f, NULL);
  else 
  {
    struct file* file = (struct file *) *(uintptr_t *) (t->open_files + fd - 2);
    lock_acquire (&filesys_lock);
    size = (file == NULL) ? 0 : file_write (file, buffer, size);
    lock_release (&filesys_lock);
  }
  return size;
}

static void sys_seek (struct intr_frame *f)
{
  void *arg1 = f->esp + ptrsize;
  if (bad_mem_access (arg1 + ptrsize))
    sys_exit (f, NULL);
  int fd = *(int *) arg1;
  unsigned position = *(unsigned *) (arg1 + ptrsize);
  struct thread *t = thread_current ();
  struct file* file = (struct file *) *(uintptr_t *) (t->open_files + fd - 2);
  if (file != NULL)
  {
    lock_acquire (&filesys_lock);
    file_seek (file, position);
    lock_release (&filesys_lock);
  }
}

static unsigned sys_tell (struct intr_frame *f)
{
  void *arg1 = f->esp + ptrsize;
  if (bad_mem_access (arg1))
    sys_exit (f, NULL);
  int fd = *(int *) arg1;
  struct thread *t = thread_current ();
  struct file* file = (struct file *) *(uintptr_t *) (t->open_files + fd - 2);
  lock_acquire (&filesys_lock);
  unsigned ret = (file != NULL) ? -1 : file_tell (file);
  lock_release (&filesys_lock);
  return ret;
}

static void sys_close (struct intr_frame *f)
{
  void *arg1 = f->esp + ptrsize;
  if (bad_mem_access (arg1))
    sys_exit (f, NULL);
  struct thread *t = thread_current ();
  int fd = *(int *) arg1;
  if (fd <= 1 || t->file_descriptor <= fd - 2)
    sys_exit (f, NULL);
  struct file *file = (struct file *) *(uintptr_t *) (t->open_files + fd - 2);
  *(uintptr_t *) (t->open_files + fd - 2) = NULL;
  if (file == NULL)
  { 
    sys_exit (f, NULL);
  }
  lock_acquire (&filesys_lock);
  file_close (file);
  lock_release (&filesys_lock);
  
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  if (bad_mem_access (f->esp))
    sys_exit (f, NULL);
  int ret = 0;
  switch (* (int *)f->esp)
  {
    case SYS_HALT:
      shutdown_power_off ();
      break;
    case SYS_EXIT:
      sys_exit (f, (f->esp + ptrsize));
      break;
    case SYS_EXEC:
      ret = sys_exec (f);
      break;
    case SYS_WAIT:
      ret = sys_wait (f);
      break;
    case SYS_CREATE:
      ret = sys_create (f);
      break;
    case SYS_REMOVE:
      ret = sys_remove (f);
      break;
    case SYS_OPEN:
      ret = sys_open (f);
      break;
    case SYS_FILESIZE:
      ret = sys_filesize (f);
      break;
    case SYS_READ:
      ret = sys_read (f);
      break;
    case SYS_WRITE:
      ret = sys_write (f);
      break;
    case SYS_SEEK:
      sys_seek (f);
      break;
    case SYS_TELL:
      ret = sys_tell (f);
      break;
    case SYS_CLOSE:
      sys_close (f);
      break;
    default:
      sys_exit (f, NULL);
      break;
  }
    f->eax = ret;
}


