#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "vm/frame.h"
#include "vm/page.h"

static void syscall_handler (struct intr_frame *);
static struct lock fs_lock;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&fs_lock);
}

static bool
validate_user_memory (struct intr_frame *f, const char *vaddr, bool writable)
{
  struct thread *cur = thread_current ();
  struct hash_iterator i;
  struct page *spte;
  if (!is_user_vaddr (vaddr))
    return false;
  // find segment which contain vaddr
  hash_first (&i, &(cur->sup_pagedir));
  while (hash_next (&i))
    {
      spte = hash_entry (hash_cur (&i), struct page, elem);
      if (spte->start_vaddr <= vaddr && vaddr < spte->end_vaddr)
      {
        break;
      }
    }
  // segment not found
  if (hash_cur (&i) == NULL)  
    {
      return false;
    }
  // segment is stack and vaddr is in red zone
  if (spte->upage == PHYS_BASE-STACK_SIZE && vaddr < f->esp-128)
  {
    return false;
  }
  // writable check
  if (writable == true && spte->writable == false)
  {
    return false;
  }
  // everything is ok, so go and get and pin user page
  pin_frame (cur->pagedir, vaddr);
  if (pagedir_get_page (cur->pagedir, vaddr) == NULL) // page is unmapper
    return load_segment (spte, vaddr);
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
  struct mmap_file *a_mf = list_entry (a, struct mmap_file, elem);
  struct mmap_file *b_mf = list_entry (b, struct mmap_file, elem);
  return a_mf->mid < b_mf->mid;
}

static mapid_t
syscall_mmap (struct intr_frame *f, int fd, void *addr)
{
  struct thread *cur = thread_current ();
  struct hash_iterator i;
  struct page *spte;
  
  struct file_desc *fde;

  struct mmap_file *mf;
  struct list_elem *e;
  
  size_t page_num;
  uint32_t file_size;
  void *upage = addr;

  if (addr == 0 || // address is 0
      (uint32_t)addr % PGSIZE != 0 || // address is not page-aligned
      fd <= 2)     // given fd is stdin, stdout or stderr
    {
      return -1;
    }

  if (!is_user_vaddr (addr))
    {
      return -1;
    }

  if (list_empty (&cur->process->fd_table))
    return -1;

  for (e = list_begin (&cur->process->fd_table);
       e != list_end (&cur->process->fd_table);
       e = list_next (e))
    {
      fde = list_entry (e, struct file_desc, elem);
      if (fde->num == fd)
        break;

      if (list_next (e) == list_end (&cur->process->fd_table))
        {
          return -1;
        }
    }

  file_size = file_length (fde->file);
  if (file_size == 0)
    return -1;

  while (upage < addr + file_size)
    {
      if (pagedir_get_page (cur->pagedir, upage) != NULL) 
        return -1;

      upage += PGSIZE;
    }

  if (!is_user_vaddr (addr+file_size-1))
    {
      return -1;
    }

  mf = malloc (sizeof *mf);
  mf->mid = -1;
  mf->file = file_reopen (fde->file);
  mf->start_addr = addr;
  mf->end_addr = addr + file_size;

  // check overlap
  hash_first (&i, &(cur->sup_pagedir));
  while (hash_next(&i))
    {
      spte = hash_entry (hash_cur (&i), struct page, elem);
      if ((spte->start_vaddr < mf->start_addr && spte->end_vaddr > mf->start_addr) ||
          (spte->start_vaddr >= mf->start_addr && spte->start_vaddr < mf->end_addr))
        {
          free (mf);
          return -1;
        }
    }

  if (list_empty (&cur->process->file_mapped))
    mf->mid = 0;
  else
    {
      int mid = 0;
      for (e = list_begin (&cur->process->file_mapped);
           e != list_end (&cur->process->file_mapped);
           e = list_next (e))
        {
          struct mmap_file *mfe = list_entry (e, struct mmap_file, elem);
          if (mid < mfe->mid)
            {
              mf->mid = mid;
              break;
            }
    
          mid++;
    
          if (list_next (e) == list_end (&cur->process->file_mapped))
            mf->mid = mid;
        }
    }

  page_num = (pg_round_down (addr + file_size) - pg_round_down (addr)) / PGSIZE + 1;
  if (!insert_page_entry (page_num, mf->start_addr, mf->end_addr, mf->start_addr,
                          mf->file, 0, file_size, true))
    {
      free (mf);
      return -1;
    }

  list_insert_ordered (&cur->process->file_mapped, &mf->elem, mf_less, NULL);
  return mf->mid;
}

static void
syscall_munmap (struct intr_frame *f, mapid_t mapid)
{
  struct thread *cur = thread_current ();
  struct mmap_file *mf;
  struct list_elem *e;

  struct page temp, *spte;

  void *upage;
  off_t offset;
  off_t file_size;

  if (list_empty (&cur->process->file_mapped))
    return;

  for (e = list_begin (&cur->process->file_mapped);
       e != list_end (&cur->process->file_mapped);
       e = list_next (e))
    {
      mf = list_entry (e, struct mmap_file, elem);
      if (mf->mid == mapid)
        break;

      if (list_next (e) == list_end (&cur->process->file_mapped))
        return;
    }

  temp.upage = mf->start_addr;
  spte = hash_entry (hash_find (&cur->sup_pagedir, &temp.elem), struct page, elem);

  file_size = file_length (mf->file);

  offset = 0;
  upage = mf->start_addr;
  while (upage < mf->end_addr)
    {
      off_t write_bytes = (file_size - offset) >= PGSIZE ? PGSIZE : file_size - offset;
      if (!validate_user_memory (f, upage, true))
        {
          return;
        }

      if (pagedir_is_dirty (cur->pagedir, upage))
        {
          file_write_at (mf->file, upage, write_bytes, offset);
        }

      remove_frame_entry (cur->pagedir, upage);
      pagedir_clear_page (cur->pagedir, upage);
      upage += PGSIZE;
      offset += PGSIZE;
      unpin_frame (cur->pagedir, upage);
    }

  bitmap_destroy (spte->first_load);
  hash_delete (&cur->sup_pagedir, &spte->elem);
  free (spte);

  file_close (mf->file);
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
  if (!validate_user_memory (f, cmd_line, false))
    {
      cur->process->exit_status = -1;
      thread_exit();
      return -1;
    }

  result = process_execute (cmd_line);
  unpin_frame (cur->pagedir, cmd_line);
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
  
  if (!validate_user_memory (f, name, false))
    {
      cur->process->exit_status = -1;
      thread_exit();
      return -1;
    }

  lock_acquire (&fs_lock);
  result = filesys_create (name, size);
  lock_release (&fs_lock);

  unpin_frame (cur->pagedir, name);
  return result;
}

static bool
syscall_remove (struct intr_frame *f, const char *name)
{
  struct process *cur = thread_current ()->process;
  bool result;
  
  if (!validate_user_memory (f, name, false))
    {
      cur->exit_status = -1;
      thread_exit();
      return -1;
    }

  lock_acquire (&fs_lock);
  result = filesys_remove (name);
  lock_release (&fs_lock);

  unpin_frame (thread_current ()->pagedir, name);
  return result;
}

static int
syscall_open (struct intr_frame *f, const char *name)
{
  struct process *cur = thread_current ()->process;
  struct file_desc *fd;

  if (!validate_user_memory (f, name, false))
    {
      //printf ("invalid mem\n");
      cur->exit_status = -1;
      thread_exit ();
      return -1;
    }

  fd = malloc (sizeof (*fd));
  fd->num = -1;

  lock_acquire (&fs_lock);
  fd->file = filesys_open (name);
  lock_release (&fs_lock);

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
  unpin_frame (thread_current ()->pagedir, name);
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

  lock_acquire (&fs_lock);
  file_close (fde->file);
  lock_release (&fs_lock);

  list_remove (&fde->elem);
  free (fde);
}

static int
syscall_read (struct intr_frame *f, int fd, char *buffer, unsigned size)
{
  struct process *cur = thread_current ()->process;
  int read = -1;
 
  int i = 0;
  while (i < size)
    {
      if (!validate_user_memory (f, buffer+i, true))
        {
          cur->exit_status = -1;
          thread_exit();
        }
      i += PGSIZE;
    }

  if (!validate_user_memory (f, buffer+size-1, true))
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

  i = 0;
  while (i < size)
    {
      unpin_frame (thread_current ()->pagedir, buffer+i);
      i += PGSIZE;
    }

  unpin_frame (thread_current ()->pagedir, buffer+size-1);
  return read;
}

static int
syscall_write (struct intr_frame *f, int fd, const char *buffer, unsigned size)
{
  struct process *cur = thread_current ()->process;
  int written = -1;
  
  int i = 0;
  while (i < size)
    {
      if (!validate_user_memory (f, buffer+i, false))
        {
          cur->exit_status = -1;
          thread_exit();
        }
      i += PGSIZE;
    }

  if (!validate_user_memory (f, buffer+size-1, false))
    {
      cur->exit_status = -1;
      thread_exit();
    }

  if (fd == STDOUT_FILENO)
    {
      int remaining = size;
      while (remaining > 0)
        {
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

  i = 0;
  while (i < size)
    {
      unpin_frame (thread_current ()->pagedir, buffer+i);
      i += PGSIZE;
    }

  unpin_frame (thread_current ()->pagedir, buffer+size-1);
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

  if (!validate_user_memory (f, f->esp, false))
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
      if (!validate_user_memory (f, f->esp+12, false))
      {
        cur->process->exit_status = -1;
        thread_exit();
      }
    // Two argument
    case SYS_CREATE:
    case SYS_SEEK:
    case SYS_MMAP:
      if (!validate_user_memory (f, f->esp+8, false))
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
      if (!validate_user_memory (f, f->esp+4, false))
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
      unpin_frame (cur->pagedir, f->esp+4);
      break;
    case SYS_EXEC:
      f->eax = syscall_exec (f, *((char **)(f->esp+4)));
      unpin_frame (cur->pagedir, f->esp+4);
      break;
    case SYS_WAIT:
      f->eax = process_wait (*((tid_t *)(f->esp+4)));
      unpin_frame (cur->pagedir, f->esp+4);
      break;
    case SYS_CREATE:
      f->eax = syscall_create (f, *((char **)(f->esp + 4)), *((unsigned *)(f->esp + 8)));
      unpin_frame (cur->pagedir, f->esp+4);
      unpin_frame (cur->pagedir, f->esp+8);
      break;
    case SYS_REMOVE:
      f->eax = syscall_remove (f, *(char **)(f->esp + 4));
      unpin_frame (cur->pagedir, f->esp+4);
      break;
    case SYS_OPEN:
      f->eax = syscall_open (f, *(char **)(f->esp + 4));
      unpin_frame (cur->pagedir, f->esp+4);
      break;
    case SYS_FILESIZE:
      f->eax = syscall_filesize (*((int *)(f->esp + 4)));
      unpin_frame (cur->pagedir, f->esp+4);
      break;
    case SYS_READ:
      f->eax = syscall_read (f, *((int *)(f->esp + 4)), *((char **)(f->esp + 8)), *((int *)(f->esp + 12)));
      unpin_frame (cur->pagedir, f->esp+4);
      unpin_frame (cur->pagedir, f->esp+8);
      unpin_frame (cur->pagedir, f->esp+12);
      break;
    case SYS_WRITE:
      f->eax = syscall_write (f, *((int *)(f->esp + 4)), *((char **)(f->esp + 8)), *((int *)(f->esp + 12)));
      unpin_frame (cur->pagedir, f->esp+4);
      unpin_frame (cur->pagedir, f->esp+8);
      unpin_frame (cur->pagedir, f->esp+12);
      break;
    case SYS_SEEK:
      syscall_seek (*((int *)(f->esp + 4)), *((unsigned *)(f->esp + 8)));
      unpin_frame (cur->pagedir, f->esp+4);
      unpin_frame (cur->pagedir, f->esp+8);
      break;
    case SYS_TELL:
      f->eax = syscall_tell (*((int *)(f->esp + 4)));
      unpin_frame (cur->pagedir, f->esp+4);
      break;
    case SYS_CLOSE:
      syscall_close (*((int *)(f->esp + 4)));
      unpin_frame (cur->pagedir, f->esp+4);
      break;
    case SYS_MMAP:
      f->eax = syscall_mmap (f, *(int *)(f->esp + 4), *(void **)(f->esp + 8));
      unpin_frame (cur->pagedir, f->esp+4);
      unpin_frame (cur->pagedir, f->esp+8);
      break;
    case SYS_MUNMAP:
      syscall_munmap (f, *(mapid_t *)(f->esp + 4));
      unpin_frame (cur->pagedir, f->esp+4);
      break;
    default:
      break;
  }
}
