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
// return true if bad user memory pointer, false otherwise
static bool bad_mem_access (void *uaddr)
{
  return (uaddr == NULL || is_kernel_vaddr (uaddr + 3) || 
          pagedir_get_page (thread_current ()->pagedir, uaddr) == NULL ||
          pagedir_get_page (thread_current ()->pagedir, uaddr + 3) == NULL);
}

void sys_exit (struct intr_frame *f, void *p)
{
  int status;
  if (p == NULL || bad_mem_access (f->esp + 4))
    status = -1;
  else
    status = *(int *) (f->esp + 4);
  
  f->eax = status;
  struct thread *cur = thread_current ();
  cur->exitstatus = status;
  struct thread *parent = cur->parent;
  //parent->childexit = status;
  thread_exit();
}
/*Runs the executable whose name is given in cmd_line, passing any given arguments, and returns the new process's program id (pid). Must return pid -1, which otherwise should not be a valid pid, if the program cannot load or run for any reason. Thus, the parent process cannot return from the exec until it knows whether the child process successfully loaded its executable. You must use appropriate synchronization to ensure this.*/
static int sys_exec(struct intr_frame *f)
{
  void *arg1 = f->esp + 4;
  if (bad_mem_access (arg1) || bad_mem_access ((void *) *(uintptr_t *) arg1))
    sys_exit (f, NULL);
  
  const char *cmd_line = (const char *) *(uintptr_t *) arg1;
  struct thread *t = thread_current ();
  int pid = process_execute (cmd_line);
  if (pid == TID_ERROR)
    return -1;
  //sema_down (&t->processexec);
  pid = (t->childexitstatus == -1) ? -1 : pid;
  return pid;
}

static int sys_wait(struct intr_frame *f)
{
  if (bad_mem_access (f->esp + 4))
    sys_exit (f, NULL);
  int pid = *(int *) (f->esp + 4);
  return process_wait (pid);
}

static bool sys_create (struct intr_frame *f)
{
  void *arg1 = f->esp + 4;
  if (bad_mem_access (arg1 + 4) || bad_mem_access ((void *) *(uintptr_t *) arg1))
    sys_exit (f, NULL);
  const char *file = (const char *) *(uintptr_t *) arg1;
  unsigned initial_size = *(unsigned *) (arg1 + 4);
  lock_acquire (&filesys_lock);
  bool ret = filesys_create (file, initial_size);
  lock_release (&filesys_lock);
  return ret;
}

static bool sys_remove (struct intr_frame *f) {
  if (bad_mem_access (f->esp + 4) || 
      bad_mem_access ((void *) *(uintptr_t *) (f->esp + 4)))
    sys_exit (f, NULL);  
  const char *file = (const char *) *(uintptr_t *) (f->esp + 4);
  lock_acquire (&filesys_lock);
  bool ret = filesys_remove (file);
  lock_release (&filesys_lock);
  return ret;
}

static int sys_open (struct intr_frame *f)
{
  void *arg1 = (f->esp + 4);
  if (bad_mem_access (arg1) || bad_mem_access ((void *) *(uintptr_t *) arg1))
    sys_exit (f, NULL);
  const char *file_name = (const char *) *(uintptr_t *) arg1;
  struct thread *t = thread_current ();
  lock_acquire (&filesys_lock);
  struct file* file = filesys_open (file_name);
  lock_release (&filesys_lock);
  if (file == NULL)
    return -1;
  if (t->open_files == NULL)
  {
    // limit number of open files to 128
    t->open_files = malloc (sizeof (uintptr_t) * 128);
    //t->open_files = palloc_get_page(PAL_ASSERT ^ PAL_ZERO);
  }
  *(uintptr_t *) (t->open_files + t->file_descriptor) = (uintptr_t) file;
  return 2 + t->file_descriptor++;
}

static int sys_filesize (struct intr_frame *f)
{
  if (bad_mem_access (f->esp + 4))
    sys_exit (f, NULL);
  int fd = *(int *) (f->esp + 4);
  struct thread *t = thread_current ();
  struct file* file = (struct file *) *(uintptr_t *) (t->open_files + fd - 2);
  lock_acquire (&filesys_lock);
  int ret = (file == NULL) ? 0 : file_length (file);
  lock_release (&filesys_lock);
  return ret;
}

static int sys_read (struct intr_frame *f)
{
  void *arg1 = f->esp + 4;
  if (bad_mem_access (arg1 + 8) || 
      bad_mem_access ((void *) *(uintptr_t *) (arg1 + 4)))
      sys_exit(f, NULL);
  struct thread *t = thread_current ();
  int fd = *(int *) arg1;
  void *buffer = (void *) *(uintptr_t *) (arg1 + 4);
  unsigned size = *(unsigned *) (arg1 + 8);
  
  if (fd == 1 || t->file_descriptor < fd - 2)
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
  void *arg1 = f->esp + 4;
  if (bad_mem_access (arg1 + 8) || 
    bad_mem_access ((void *) *(uintptr_t *) (arg1 + 4)))
    sys_exit(f, NULL);
  int fd = *(int *) arg1;
  void *buffer = (const void *) *(uintptr_t *) (arg1 + 4);
  unsigned size = *(unsigned *) (arg1 + 8);
  struct thread *t = thread_current ();
  if (fd == 1) 
    putbuf (buffer, size);
  else if (fd == 0 || t->file_descriptor < fd - 2)
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
  void *arg1 = f->esp + 4;
  if (bad_mem_access (arg1 + 4))
    sys_exit (f, NULL);
  int fd = *(int *) arg1;
  unsigned position = *(unsigned *) (arg1 + 4);
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
  void *arg1 = f->esp + 4;
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
  void *arg1 = f->esp + 4;
  if (bad_mem_access (arg1))
    sys_exit (f, NULL);
  struct thread *t = thread_current ();
  int fd = *(int *) arg1;
  if (fd <= 1 || t->file_descriptor < fd - 2)
    sys_exit (f, NULL);
  if (t->open_files == NULL)
    sys_exit (f, NULL);
  struct file *file = (struct file *) *(uintptr_t *) (t->open_files + fd - 2);
  *(uintptr_t *) (t->open_files + fd - 2) = NULL;
  if (file == NULL)
    sys_exit (f, NULL);
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
      sys_exit (f, (f->esp + 4));
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

/*


FAIL tests/userprog/no-vm/multi-oom 


pintos-mkdisk filesys.dsk --filesys-size=2
pintos -f -q

pintos -p tests/userprog/no-vm/multi-oom -a multi-oom -- -q


instead of using array for children, use linked list
a thread can only wait for one child at a time, so we
use just childexit for the child's exit status
we need to ensure that the child that has just exited notifies the
parent that it has exited,
also when a thread exits, need to call process_wait on each of its children







a zombie waiting for its parent -> zombie thread has finished executing, but parent has not or will not call wait on that thread.
*/

