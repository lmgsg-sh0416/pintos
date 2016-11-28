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
  struct hash_elem *e;
  struct page temp, *spte;
  if (!is_user_vaddr (vaddr))
    return false;
  if (pagedir_get_page (cur->pagedir, vaddr) == NULL) // page is unmapper
    {
      // find segment which contain vaddr
      temp.upage = pg_round_down (vaddr);
      e = hash_find (&cur->sup_pagedir, &temp.elem);

      // segment not found
      if (e == NULL)  
        return false;
      spte = hash_entry (e, struct page, elem);
      // segment is stack and vaddr is in red zone
      if (spte->upage == PHYS_BASE-STACK_SIZE && vaddr < f->esp-128)  
        return false;
      // load segment
      return load_segment (spte, vaddr);
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

static bool
mf_less (const struct list_elem *a, const struct list_elem *b, void *aux UNUSED)
{
  struct map_file *a_mf = list_entry (a, struct map_file, elem);
  struct map_file *b_mf = list_entry (b, struct map_file, elem);
  return a_mf->mid < b_mf->mid;
}

static mapid_t
syscall_mmap (int fd, void *addr)
{
  struct thread *cur = thread_current ();
  struct list_elem *e;
  void *upage = addr;

  struct file_desc *fde;
  struct map_file *mf;
  int32_t num_pages;
  off_t size_file;

  if (!is_user_vaddr (addr))
    {
      return -1;
    }

  if (addr == 0 ||                      // addr 0 is unmappable
      (uint32_t)addr % PGSIZE != 0 ||   // not page-aligned
      fd <= 2)                          // stdin, stdout, stderr or other invalid fd number
    {
      return -1;
    }

  // fd table is empty - must fail
  if (list_empty (&cur->process->fd_table))
    return -1;

  // file descriptor search
  for (e = list_begin (&cur->process->fd_table); e != list_end (&cur->process->fd_table); e = list_next (e))
    {
      fde = list_entry (e, struct file_desc, elem);
      if (fde->num == fd)
        break;

      if (list_next (e) == list_end (&cur->process->fd_table))
        return -1;
    }

  size_file = file_length (fde->file);
  num_pages = size_file / PGSIZE;
  if (size_file % PGSIZE != 0)
    num_pages++;

  // check the file is mappable at the given address
  while (num_pages > 0) 
    {
      if (pagedir_get_page (cur->pagedir, upage) != NULL)
        {
          return -1;
        }

      num_pages--;
      upage += PGSIZE;
    }
  
  // it's OK to insert
  if (!insert_page_entry (PAGE_FILE, addr, addr + size_file, 
                          addr, fde->file, 0, size_file, true))
    {
      return -1;
    }

  mf = malloc (sizeof *mf);
  mf->file = fde->file;
  mf->addr = addr;
  mf->mid = -1;

  // allocate map id
  if (list_empty (&cur->process->mf_table)) 
    {
      mf->mid = 0;
    }
  else
    {
      int mid = 0;
      for (e = list_begin (&cur->process->mf_table); e != list_end (&cur->process->mf_table); e = list_next (e))
        {
          struct map_file *mfe = list_entry (e, struct map_file, elem);
          if (mid < mfe->mid)
            {
              mf->mid = mid;
              break;
            }

          mid++;

          if (list_next (e) == list_end (&cur->process->mf_table))
            mf->mid = mid;
        }
    }

  list_insert_ordered (&cur->process->mf_table, &mf->elem, mf_less, NULL);
  return mf->mid;
}

static void
syscall_munmap (mapid_t mapid)
{
  struct thread *cur = thread_current ();
  struct map_file *mf;
  struct list_elem *e;
  struct file *reopened;

  int32_t num_pages;
  off_t size_file;
  void *upage;
  
  for (e = list_begin (&cur->process->mf_table); e != list_end (&cur->process->mf_table); e = list_next (e))
    {
      mf = list_entry (e, struct map_file, elem);
      if (mf->mid == mapid)
        break;

      if (list_next (e) == list_end (&cur->process->mf_table))
        return;
    }

  reopened = file_reopen (mf->file);

  upage = mf->addr;
  size_file = file_length (reopened);
  num_pages = size_file / PGSIZE;
  if (size_file % PGSIZE != 0)
    num_pages++;

  while (num_pages > 0) 
    {
      if (pagedir_is_dirty (&cur->pagedir, upage))
        {
          off_t diff = upage - mf->addr;
          uint32_t read_bytes = size_file >= diff ? size_file - diff : 0;
          file_write_at (reopened, upage, read_bytes, diff);
        }
      pagedir_clear_page (&cur->pagedir, upage);

      num_pages--;
      upage += PGSIZE;
    }

  file_close (reopened);
  list_remove (&mf->elem);
  free (mf);
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
    case SYS_MMAP:
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
    case SYS_MUNMAP:
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
    case SYS_MMAP:
      f->eax = syscall_mmap (*(int *)(f->esp + 4), *(void **)(f->esp + 8));
      break;
    case SYS_MUNMAP:
      syscall_munmap (*(mapid_t *)(f->esp + 4));
      break;
    default:
      break;
  }
}

