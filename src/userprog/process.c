#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/page.h"
#include "vm/swap.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy, *parse_copy;
  tid_t tid;
  char *token, *save_ptr, *parse_ptr;
  int len;
  struct process *p;
  struct thread *cur = thread_current ();
  enum intr_level old_level;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  parse_copy = palloc_get_page (PAL_ZERO);
  parse_ptr = parse_copy;
  /* Parsing */
  for (token = strtok_r (fn_copy, " ", &save_ptr); token != NULL;
       token = strtok_r (NULL, " ", &save_ptr))
    {
      len = strlen (token);
      strlcpy(parse_ptr, token, len+1);
      parse_ptr += (len+1);
    }

  palloc_free_page (fn_copy);
  fn_copy = parse_copy;

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (fn_copy, PRI_DEFAULT, start_process, fn_copy);
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy); 
  /* If thread is created successfully, */
  else
  {
    /* Child thread can execute start_process until sema_up(exec_sema2).
     * Make struct process and initialize. */
    old_level = intr_disable ();
    p = (struct process*) malloc (sizeof *p);
    p->process_id = tid;
    sema_init (&(p->wait_sema), 0);
    p->is_parent_dead = false;
    p->is_child_dead = false;
    list_push_back (&(cur->child_process), &(p->elem));
    list_init (&p->fd_table);
    intr_set_level (old_level);
    sema_up (&(cur->exec_sema2));
    /* Parent thread wait until success is updated */
    sema_down (&(cur->exec_sema));
    if (p->success == false)
    {
      old_level = intr_disable ();
      list_remove (&(p->elem));
      free (p);
      intr_set_level (old_level);
      return TID_ERROR;
    }
  }
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;
  char *esp_char, *fn_ptr;
  uint32_t *esp_int;
  uint32_t size, num = 0;
  struct list_elem *e;
  struct process *p;
  struct thread *cur = thread_current ();

  /* Wait until struct process is pushed back into parent's child_process */
  sema_down (&(cur->parent->exec_sema2));

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  if (success)
  {
    /* Algorithm for find size of parsing string and memcpy */
    esp_char = (char*)if_.esp;
    fn_ptr = file_name;
    while (fn_ptr+1-file_name<+PGSIZE && !(*fn_ptr=='\0' && *(fn_ptr+1)=='\0'))
      fn_ptr++;
    size = fn_ptr-file_name+1;
    esp_char -= size;
    memcpy (esp_char, file_name, size);
    /* word align */
    esp_int = (uint32_t*)if_.esp - 1;
    while ((void*)esp_int > (void*)esp_char)
      esp_int--;
    /* argv and argc */
    esp_int--;
    *(esp_int--) = 0;
    for (fn_ptr=PHYS_BASE-1; fn_ptr>=esp_char; fn_ptr--)
      if (*(fn_ptr-1) == '\0')
        {
          *(esp_int--) = (uint32_t*)fn_ptr;
          num++;
        }
    *(esp_int--) = (uint32_t*)esp_int+1;
    *(esp_int--) = num; 
    if_.esp = (void*)esp_int;
    unpin_frame (cur->pagedir, PHYS_BASE-PGSIZE);
  }

  /* Find child process */
  for (e = list_begin (&(cur->parent->child_process)); e != list_end (&(cur->parent->child_process));
       e = list_next (e))
  {
    p = list_entry (e, struct process, elem);
    if (p->process_id == cur->tid)
      break;
  }
  ASSERT (e != list_end (&(cur->parent->child_process)));

  if (success)
    cur->process = p;
  
  p->success = success;
  /* Wake up parent process */
  sema_up (&(cur->parent->exec_sema));

  /* If load failed, quit. */
  palloc_free_page (file_name);

  if (!success) 
    thread_exit ();

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
  struct thread *cur = thread_current ();
  struct list_elem *e;
  struct process *p;
  int exit_status;
  enum intr_level old_level;

  old_level = intr_disable ();
  for (e = list_begin (&(cur->child_process)); e != list_end (&(cur->child_process));
       e = list_next (e))
    {
      p = list_entry (e, struct process, elem);
      if (p->process_id == child_tid)
        break;
    }
  if (e == list_end (&(cur->child_process)))
    return -1;
  sema_down (&(p->wait_sema));
  /* It means that corresponding child process is terminated 
   * so that we can remove struct process.
   * Two ways to remove struct process
   * 1. Here
   * 2. process_exit */
  exit_status = p->exit_status;
  list_remove (&(p->elem));
  free (p);
  intr_set_level (old_level);
  return exit_status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;
  struct list_elem *e;
  struct process *p;
  enum intr_level old_level;

  if (cur->process != NULL)
    {
      printf ("%s: exit(%d)\n", cur->name, cur->process->exit_status);
      
      if (!list_empty (&cur->process->fd_table))
        {
          struct file_desc *fde;
          for (e = list_begin (&cur->process->fd_table); e != list_end (&cur->process->fd_table); )
            {
              fde = list_entry (e, struct file_desc, elem);
              e = list_next (e);
              file_close (fde->file);
              free (fde);
            }
        }
    }

  if (cur->executable != NULL)
    file_close (cur->executable);
  
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      free_swap_slot_by_pd (cur->pagedir);
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
  old_level = intr_disable ();
  /* It MUST be acceptable and valid for process */ 
  if (cur->process != NULL)
  {
    sema_up (&(cur->process->wait_sema));
    cur->process->is_child_dead = true;
    if (cur->process->is_parent_dead)
      free (cur->process);
  }
  /* Destroy child_process chain */
  while (!list_empty (&(cur->child_process)))
  {
    e = list_pop_front (&(cur->child_process));
    p = list_entry (e, struct process, elem);
    list_remove (&(p->elem));
    p->is_parent_dead = true;
    if (p->is_child_dead)
      free (p);
  }
  intr_set_level (old_level);
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();
  init_sup_pagedir ();

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct page *spte = (struct page*) malloc (sizeof *spte);
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              uint32_t start_vaddr = phdr.p_vaddr;
              uint32_t end_vaddr = start_vaddr + phdr.p_memsz;
              void *upage = start_vaddr & ~PGMASK;
              off_t file_offset = phdr.p_offset & ~PGMASK;
              uint32_t read_bytes;
              bool writable = (phdr.p_flags & PF_W) != 0;
              size_t page_num = (pg_round_down (end_vaddr) - pg_round_down (start_vaddr))/PGSIZE + 1;

              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                }
              if (!insert_page_entry (page_num, start_vaddr, end_vaddr, upage, file_offset, read_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;
  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  if (success)
    {
      t->executable = file;
      file_deny_write (file);
    }
  else
    file_close (file);
  return success;
}


/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* load_segment() helpers. */
static bool load_segment_from_file (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, bool writable);
static bool load_segment_from_swap (uint8_t *upage, bool writable);

static struct lock load_lock;

void 
init_load_lock (void)
{
  lock_init (&load_lock);
}

bool
load_segment (struct page *spte, void *vaddr)
{
  struct thread *cur = thread_current ();
  void *page = pg_round_down (vaddr);
  off_t diff = page - spte->upage;
  
  lock_acquire (&load_lock);
  /* Load from file */
  if (bitmap_test (spte->first_load, diff/PGSIZE) == false)
    {
      off_t off = spte->file_offset + diff;
      uint32_t read_bytes = spte->read_bytes>=diff ? spte->read_bytes-diff : 0;
      read_bytes = read_bytes > PGSIZE ? PGSIZE : read_bytes;
      if (!load_segment_from_file (cur->executable, off, page, read_bytes, spte->writable))
        {
          lock_release (&load_lock);
          return false;
        }
      bitmap_set (spte->first_load, diff/PGSIZE, true);
    }
  /* Load from swap */
  else
    {
      if (!load_segment_from_swap (page, spte->writable))
        {
          lock_release (&load_lock);
          return false;
        }
    }
  lock_release (&load_lock);
  return true;
}


/* Load from file just one page */
static bool
load_segment_from_file (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, bool writable) 
{
  struct thread *cur = thread_current ();
  ASSERT (0 <= read_bytes && read_bytes <= PGSIZE);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);

  /* Get a page of memory. */
  uint8_t *kpage = insert_frame_entry (cur->pagedir, upage, PAL_USER);
  if (kpage == NULL)
    return false;

  /* Load this page. */
  if (file_read (file, kpage, read_bytes) != (int) read_bytes)
    {
      remove_frame_entry (cur->pagedir, upage);
      return false; 
    }
  memset (kpage + read_bytes, 0, PGSIZE - read_bytes);

  /* Add the page to the process's address space. */
  if (!install_page (upage, kpage, writable)) 
    {
      remove_frame_entry (cur->pagedir, upage);
      return false; 
    }

  return true;
}

/* Load from file just one page */
static bool
load_segment_from_swap (uint8_t *upage, bool writable) 
{
  struct thread *cur = thread_current ();
  uint8_t *kpage;
  ASSERT (pg_ofs (upage) == 0);

  /* Get a page of memory. */
  kpage = insert_frame_entry (cur->pagedir, upage, PAL_USER);
  if (kpage == NULL)
      return false;

  /* Load this page from swap */
  free_swap_slot_by_address (cur->pagedir, upage, kpage);

  /* Add the page to the process's address space. */
  if (!install_page (upage, kpage, writable)) 
    {
      remove_frame_entry (cur->pagedir, upage);
      return false; 
    }

  return true;
}

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  struct thread *cur = thread_current ();
  uint8_t *kpage;
  bool success = false;
  struct hash_elem *e;
  struct page p, *spte;

  lock_acquire (&load_lock);
  kpage = insert_frame_entry (cur->pagedir, PHYS_BASE-PGSIZE, PAL_USER | PAL_ZERO);
  if (!insert_page_entry (STACK_SIZE/PGSIZE, PHYS_BASE-STACK_SIZE, PHYS_BASE, PHYS_BASE-STACK_SIZE, 0, 0, true))
    {
      lock_release (&load_lock);
      return success;
    }
  // set mark to stack first page
  p.upage = PHYS_BASE-STACK_SIZE;
  e = hash_find (&cur->sup_pagedir, &p.elem);
  spte = hash_entry (e, struct page, elem);
  bitmap_set (spte->first_load, STACK_SIZE/PGSIZE-1, true);

  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        remove_frame_entry (cur->pagedir, PHYS_BASE-PGSIZE);
    }
  lock_release (&load_lock);
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
