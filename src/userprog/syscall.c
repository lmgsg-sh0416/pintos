#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  if (!is_user_vaddr (f->esp))
    thread_exit();

  int num = *((int *)f->esp);
  
  switch (num) {
    case SYS_HALT:
      printf ("HALT!\n");
      break;
    case SYS_EXIT:
      printf ("EXIT!\n");
      if (!is_user_vaddr (f->esp))
        thread_exit();

      int status = *((int *)f->esp);

      thread_current ()->status = status;

      thread_exit();
      break;
    case SYS_EXEC:
      printf ("EXEC!\n");
      break;
    case SYS_WAIT:
      printf ("WAIT!\n");
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

      int size = *((int *)(f->esp + 4));
      char *buffer = (char *)(f->esp + 8);
      int fd = *((int *)(f->esp + 12));

      if (fd == 1)
        {
          putbuf (buffer, size);
        }
      else
        {
          
        }

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
