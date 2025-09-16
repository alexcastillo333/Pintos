#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/palloc.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
static void syscall_handler (struct intr_frame *);

static void sys_exit(int status)
{
  thread_exit();
}

static int sys_exec(const char *cmd_line)
{
  return 0;
}

static int sys_wait(int pid)
{
  while (pid > 0)
    pid++;
  return 0;
}

static bool sys_create (const char *file, unsigned initial_size)
{
  return filesys_create (file, initial_size);
}

static bool sys_remove (const char *file) {
  return filesys_remove (file);
}

static int sys_open (const char *file)
{
  struct thread *t = thread_current ();
  struct file* f = filesys_open (file);
  if (f == NULL)
    return -1;
  if (t->open_files == NULL)
  {
    t->open_files = palloc_get_page(PAL_ASSERT & PAL_ZERO);
  }
  *(uintptr_t *) *(t->open_files + t->file_descriptor) = (uintptr_t) f;
  return 2 + t->file_descriptor++;
}

static int sys_filesize (int fd)
{
  struct thread *t = thread_current ();
  struct file* f = (struct file *) *(uintptr_t *) *(t->open_files + fd - 2);
  return (f == NULL) ? 0 : file_length (f);
}

static int sys_read (int fd, void *buffer, unsigned size)
{
  if (fd <= 1) 
  {
    input_getc();
    size = 1;
    //putbuf (buffer, size);
  // is fd == 0 possilbe? write to std input?
  } else {
    struct thread *t = thread_current ();
    struct file* f = (struct file *) *(uintptr_t *) *(t->open_files + fd - 2);
    size = (f == NULL) ? -1 : file_read (f, buffer, size);
  }
  return size;
}

static int sys_write(int fd, const void *buffer, unsigned size)
{
  
  if (fd <= 1) 
  {
    putbuf (buffer, size);
  // is fd == 0 possilbe? write to std input?
  } else {
    struct thread *t = thread_current ();
    struct file* f = (struct file *) *(uintptr_t *) *(t->open_files + fd - 2);
    size = (f == NULL) ? 0 : file_write (f, buffer, size);
  }
  return size;
}

static void sys_seek (int fd, unsigned position)
{
  struct thread *t = thread_current ();
  struct file* f = (struct file *) *(uintptr_t *) *(t->open_files + fd - 2);
  if (f != NULL)
    file_seek (f, position);
}

static unsigned sys_tell (int fd)
{
  struct thread *t = thread_current ();
  struct file* f = (struct file *) *(uintptr_t *) *(t->open_files + fd - 2);
  return (f != NULL) ? -1 : file_tell (f);
}

static void sys_close (int fd)
{
  struct thread *t = thread_current ();
  struct file* f = (struct file *) *(uintptr_t *) *(t->open_files + fd - 2);
  if (f != NULL)
    file_close (f);
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int ret = 0;
  switch (* (int *)f->esp)
  {
    case SYS_HALT:
      shutdown_power_off ();
      break;
    case SYS_EXIT:
      sys_exit (0);
      break;
    case SYS_EXEC:
      ret = sys_exec("");
      break;
    case SYS_WAIT:
      ret = sys_wait(1);
      break;
    case SYS_CREATE:
      ret = sys_create ((const char *) *(uintptr_t *) (f->esp + 4),
                        *(int *) (f->esp + 8));
      break;
    case SYS_REMOVE:
      ret = sys_remove ((const char *) *(uintptr_t *) (f->esp + 4));
      break;
    case SYS_OPEN:
      ret = sys_open ((const char *) *(uintptr_t *) (f->esp + 4));
      break;
    case SYS_FILESIZE:
      ret = sys_filesize (*(int *) (f->esp + 4));
      break;
    case SYS_READ:
      ret = sys_read (*(int *) (f->esp + 4), 
                      (void *) *(uintptr_t *) (f->esp + 8), 
                      *(unsigned *) (f->esp + 12));
      break;
    case SYS_WRITE:
      ret = sys_write (*(int *) (f->esp + 4), 
                       (const void *) *(uintptr_t *) (f->esp + 8), 
                       *(unsigned *) (f->esp + 12));
      break;
    case SYS_SEEK:
      sys_seek (*(int *) (f->esp + 4), *(unsigned *) (f->esp + 8));
      break;
    case SYS_TELL:
      ret = sys_tell (*(int *) (f->esp + 4));
      break;
    case SYS_CLOSE:
      sys_close (*(int *) (f->esp + 4));
      break;
  }
    f->eax = ret;
  //printf ("system call!\n");
  //thread_exit ();
}

// pintos -v -k -T 60 --qemu  --filesys-size=2 -p tests/userprog/args-multiple -a args-multiple -- -q  -f run 'args-multiple some arguments for you!' < /dev/null 2> tests/userprog/args-multiple.errors > tests/userprog/args-multiple.output