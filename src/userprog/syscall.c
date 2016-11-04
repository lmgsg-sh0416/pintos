#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static bool
validate_user_memory (void *vaddr)
{
  struct thread *cur = thread_current ();
  return (is_user_vaddr (vaddr) && pagedir_get_page (cur->pagedir, vaddr) != NULL);
}

static void
syscall_exit (int status)
{
  thread_current ()->exit_status = status;
  thread_exit();
}

static void
syscall_exec (const char *cmd_line)
{
  process_execute (cmd_line);
}

static void
syscall_handler (struct intr_frame *f) 
{
  struct thread *cur = thread_current ();
  int syscall_num;
  if (!validate_user_memory (f->esp))
  {
    cur->exit_status = -1;
    thread_exit();
  }
  syscall_num = *((int *)f->esp);
  
  switch (syscall_num) {
    case SYS_HALT:
      shutdown_power_off ();
      break;
    case SYS_EXIT:
      if (!validate_user_memory (f->esp+4))
      {
        cur->exit_status = -1;
        thread_exit();
      }
      syscall_exit (*((int *)(f->esp+4)));
      break;
    case SYS_EXEC:
      if (!validate_user_memory (f->esp+4))
      {
        cur->exit_status = -1;
        thread_exit();
      }
      syscall_exec (*((char **)(f->esp+4)));
      break;
    case SYS_WAIT:
      if (!validate_user_memory (f->esp+4))
      {
        cur->exit_status = -1;
        thread_exit();
      }
      f->eax = process_wait (*((tid_t *)(f->esp+4)));
      break;
    case SYS_CREATE:
      printf ("CREATE!\n");
      break;
    case SYS_REMOVE:
      printf ("REMOVE!\n");
      break;
    case SYS_OPEN:
      printf ("OPEN!\n");
      break;
    case SYS_FILESIZE:
      printf ("FILESIZE!\n");
      break;
    case SYS_READ:
      printf ("READ!\n");
      break;
    case SYS_WRITE:
      if (!is_user_vaddr (f->esp + 4) ||
          !is_user_vaddr (f->esp + 8) ||
          !is_user_vaddr (f->esp + 12))
        thread_exit();
      int fd = *((int *)(f->esp + 4));
      char *buffer = *((char **)(f->esp + 8));
      int size = *((int *)(f->esp + 12));
      if (fd == 1)
        putbuf (buffer, size);
      break;
    case SYS_SEEK:
      printf ("SEEK!\n");
      break;
    case SYS_TELL:
      printf ("TELL!\n");
      break;
    case SYS_CLOSE:
      printf ("CLOSE!\n");
      break;
    default:
      break;
  }
}

