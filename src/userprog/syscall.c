#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static bool
validate_user_memory (struct intr_frame *f, const char *vaddr)
{
  struct thread *cur = thread_current ();
  struct hash_iterator i;
  struct page *spte;
  if (!is_user_vaddr (vaddr))
    return false;
  if (pagedir_get_page (cur->pagedir, vaddr) == NULL) // page is unmapper
    {
      // find segment which contain vaddr
      hash_first (&i, &(cur->sup_pagedir));
      while (hash_next (&i))
        {
          spte = hash_entry (hash_cur (&i), struct page, elem);
          if (spte->start_vaddr <= vaddr && vaddr < spte->end_vaddr)
            break;
        }
      // segment not found
      if (hash_cur (&i) == NULL)  
        return false;
      // segment is stack and vaddr is in red zone
      if (spte->upage == PHYS_BASE-STACK_SIZE && vaddr < f->esp-128)  
        return false;
      // load segment
      if (spte->type == PAGE_FILE || spte->type == PAGE_ZERO)
        {
          void *page = pg_round_down (vaddr);
          off_t diff = page - spte->upage;
          off_t off = spte->file_offset + diff;
          uint32_t read_bytes = spte->read_bytes>=diff ? spte->read_bytes-diff : 0;
          read_bytes = read_bytes > PGSIZE ? PGSIZE : read_bytes;
          return load_segment (cur->executable, off, page, read_bytes, spte->writable);
        }
      // need to implement swap
      else
        return false;
    }
  return true;
}

static bool
fd_less (const struct list_elem *a, const struct list_elem *b, void *aux UNUSED)
{
  struct file_desc *a_fd = list_entry (a, struct file_desc, elem);
  struct file_desc *b_fd = list_entry (b, struct file_desc, elem);
  return a_fd->num < b_fd->num;
}

static void
syscall_exit (int status)
{
  thread_current ()->process->exit_status = status;
  thread_exit();
}

static tid_t
syscall_exec (struct intr_frame *f, const char *cmd_line)
{
  struct thread *cur = thread_current ();
  tid_t result;
  if (!validate_user_memory (f, cmd_line))
  {
    cur->process->exit_status = -1;
    thread_exit();
    return -1;
  }
  result = process_execute (cmd_line);
  if (result == TID_ERROR)
    return -1;
  else
    return result;
}

static bool
syscall_create (struct intr_frame *f, const char *name, int32_t size)
{
  struct thread *cur = thread_current ();
  bool result;
  
  if (!validate_user_memory (f, name))
  {
    cur->process->exit_status = -1;
    thread_exit();
    return -1;
  }

  result = filesys_create (name, size);

  return result;
}

static bool
syscall_remove (struct intr_frame *f, const char *name)
{
  struct process *cur = thread_current ()->process;
  bool result;
  
  if (!validate_user_memory (f, name))
  {
    cur->exit_status = -1;
    thread_exit();
    return -1;
  }

  result = filesys_remove (name);

  /* what if the file is opened? */

  return result;
}

static int
syscall_open (struct intr_frame *f, const char *name)
{
  struct process *cur = thread_current ()->process;
  struct file_desc *fd;

  if (!validate_user_memory (f, name))
    {
      cur->exit_status = -1;
      thread_exit ();

      return -1;
    }

  fd = malloc (sizeof (*fd));
  fd->num = -1;

  fd->file = filesys_open (name);
  if (fd->file == NULL)
    {
      free (fd);
      return -1;
    }

  if (list_empty (&cur->fd_table))
    fd->num = 3;
  else 
    {
      int num = 3;
      struct list_elem *e;
      for (e = list_begin (&cur->fd_table); e != list_end (&cur->fd_table); e = list_next (e))
        {
          struct file_desc *fde = list_entry (e, struct file_desc, elem);
          if (num < fde->num)
            {
              fd->num = num;
              break;
            }

          num++;

          if (list_next (e) == list_end (&cur->fd_table))
            fd->num = num;
        }
    }

  list_insert_ordered (&cur->fd_table, &fd->elem, fd_less, NULL);

  return fd->num;
}

static void
syscall_close (int fd)
{
  struct process *cur = thread_current ()->process;

  struct file_desc *fde;
  struct list_elem *e;
  if (list_empty (&cur->fd_table))
    return;

  for (e = list_begin (&cur->fd_table); e != list_end (&cur->fd_table); e = list_next (e))
    {
      fde = list_entry (e, struct file_desc, elem);
      if (fde->num == fd)
        break;

      if (list_next (e) == list_end (&cur->fd_table))
        return;
    }

  file_close (fde->file);
  list_remove (&fde->elem);
  free (fde);
}

static int
syscall_read (struct intr_frame *f, int fd, char *buffer, unsigned size)
{
  struct process *cur = thread_current ()->process;
  int read = -1;
 
  if (!validate_user_memory (f, buffer) ||
      !validate_user_memory (f, buffer + size - 1))
  {
    cur->exit_status = -1;
    thread_exit();
  }

  if (fd == STDIN_FILENO)
    for (read = 0; read < size; read++)
      *(buffer + read) = input_getc ();
  else if (fd != STDOUT_FILENO)
    {
      struct file_desc *fde;
      struct list_elem *e;
      if (list_empty (&cur->fd_table))
        return read;

      for (e = list_begin (&cur->fd_table); e != list_end (&cur->fd_table); e = list_next (e))
        {
          fde = list_entry (e, struct file_desc, elem);
          if (fde->num == fd)
            break;

          if (list_next (e) == list_end (&cur->fd_table))
            return read;
        }

      read = file_read (fde->file, buffer, size);
    }

  return read;
}

static int
syscall_write (struct intr_frame *f, int fd, const char *buffer, unsigned size)
{
  struct process *cur = thread_current ()->process;
  int written = -1;
  
  if (!validate_user_memory (f, buffer) ||
      !validate_user_memory (f, buffer + size - 1))
  {
    cur->exit_status = -1;
    thread_exit();
  }

  if (fd == STDOUT_FILENO)
    {
      int remaining = size;
      while (remaining > 0)
        {
          if (!validate_user_memory (f, buffer + (remaining - size)))
            {
              cur->exit_status = -1;
              thread_exit ();
              return -1;
            }

          putbuf (buffer + (remaining - size), (remaining % 101));
          remaining -= 100;
        }

      written = size;
    }
  else if (fd != STDIN_FILENO)
    {
      struct file_desc *fde;
      struct list_elem *e;
      if (list_empty (&cur->fd_table))
        return written;

      for (e = list_begin (&cur->fd_table); e != list_end (&cur->fd_table); e = list_next (e)) 
        {
          fde = list_entry (e, struct file_desc, elem);
          if (fde->num == fd)
            break;
          
          if (list_next (e) == list_end (&cur->fd_table))
            return written;
        }

      written = file_write (fde->file, buffer, size);
    }

  return written;
}

static int 
syscall_filesize (int fd)
{
  struct process *cur = thread_current ()->process;
  int size = -1;

  struct file_desc *fde;
  struct list_elem *e;
  if (list_empty (&cur->fd_table))
    return size;

  for (e = list_begin (&cur->fd_table); e != list_end (&cur->fd_table); e = list_next (e))
    {
      fde = list_entry (e, struct file_desc, elem);
      if (fde->num == fd)
        break;

      if (list_next (e) == list_end (&cur->fd_table))
        return size;
    }

  size = file_length (fde->file);
  return size;
}

static void
syscall_seek (int fd, unsigned position)
{
  struct process *cur = thread_current ()->process;

  struct file_desc *fde;
  struct list_elem *e;
  if (list_empty (&cur->fd_table))
    return;

  for (e = list_begin (&cur->fd_table); e != list_end (&cur->fd_table); e = list_next (e))
    {
      fde = list_entry (e, struct file_desc, elem);
      if (fde->num == fd)
        break;

      if (list_next (e) == list_end (&cur->fd_table))
        return;
    }
  
  file_seek (fde->file, position);
}

static unsigned
syscall_tell (int fd)
{
  struct process *cur = thread_current ()->process;
  unsigned pos = 0;

  struct file_desc *fde;
  struct list_elem *e;
  if (list_empty (&cur->fd_table))
    return pos;

  for (e = list_begin (&cur->fd_table); e != list_end (&cur->fd_table); e = list_next (e))
    {
      fde = list_entry (e, struct file_desc, elem);
      if (fde->num == fd)
        break;

      if (list_next (e) == list_end (&cur->fd_table))
        return pos;
    }

  pos = file_tell (fde->file);
  return pos;
}

static void
syscall_handler (struct intr_frame *f) 
{
  struct thread *cur = thread_current ();
  int syscall_num;
  
  ASSERT (cur->process != NULL);

  if (!validate_user_memory (f, f->esp))
  {
    cur->process->exit_status = -1;
    thread_exit();
  }

  syscall_num = *((int *)f->esp);
  
  // Validate argument address
  // CAUTION: Need to additional validate if value is pointer
  switch (syscall_num) {
    // Three argument
    case SYS_READ:
    case SYS_WRITE:
      if (!validate_user_memory (f, f->esp+12))
      {
        cur->process->exit_status = -1;
        thread_exit();
      }
    // Two argument
    case SYS_CREATE:
    case SYS_SEEK:
      if (!validate_user_memory (f, f->esp+8))
      {
        cur->process->exit_status = -1;
        thread_exit();
      }
    // One argument
    case SYS_EXIT:
    case SYS_EXEC:
    case SYS_WAIT:
    case SYS_REMOVE:
    case SYS_OPEN:
    case SYS_FILESIZE:
    case SYS_TELL:
    case SYS_CLOSE:
      if (!validate_user_memory (f, f->esp+4))
      {
        cur->process->exit_status = -1;
        thread_exit();
      }
    default:
      break;
  }

  switch (syscall_num) {
    case SYS_HALT:
      shutdown_power_off ();
      break;
    case SYS_EXIT:
      syscall_exit (*((int *)(f->esp+4)));
      break;
    case SYS_EXEC:
      f->eax = syscall_exec (f, *((char **)(f->esp+4)));
      break;
    case SYS_WAIT:
      f->eax = process_wait (*((tid_t *)(f->esp+4)));
      break;
    case SYS_CREATE:
      f->eax = syscall_create (f, *((char **)(f->esp + 4)), *((unsigned *)(f->esp + 8)));
      break;
    case SYS_REMOVE:
      f->eax = syscall_remove (f, *(char **)(f->esp + 4));
      break;
    case SYS_OPEN:
      f->eax = syscall_open (f, *(char **)(f->esp + 4));
      break;
    case SYS_FILESIZE:
      f->eax = syscall_filesize (*((int *)(f->esp + 4)));
      break;
    case SYS_READ:
      f->eax = syscall_read (f, *((int *)(f->esp + 4)), *((char **)(f->esp + 8)), *((int *)(f->esp + 12)));
      break;
    case SYS_WRITE:
      f->eax = syscall_write (f, *((int *)(f->esp + 4)), *((char **)(f->esp + 8)), *((int *)(f->esp + 12)));
      break;
    case SYS_SEEK:
      syscall_seek (*((int *)(f->esp + 4)), *((unsigned *)(f->esp + 8)));
      break;
    case SYS_TELL:
      f->eax = syscall_tell (*((int *)(f->esp + 4)));
      break;
    case SYS_CLOSE:
      syscall_close (*((int *)(f->esp + 4)));
      break;
    default:
      break;
  }
}

