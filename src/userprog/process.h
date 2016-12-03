#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "filesys/directory.h"
#define STACK_SIZE (1<<23)

struct file_desc
  {
    int num;
    struct file *file;
    struct dir *dir;
    bool is_directory;
    struct list_elem elem;
  };

struct mmap_file
  {
    int mid;
    struct file *file;
    void *start_addr;
    void *end_addr;
    struct list_elem elem;
  };

struct process
  {
    struct list_elem elem;          /* element of child process */
    tid_t process_id;               /* equal to thread id */
    int exit_status;                /* exit_status of this process */
    struct semaphore wait_sema;     /* semaphore for this process */
    bool success;                   /* load success? */
    bool is_parent_dead;            /* is parent dead? */
    bool is_child_dead;             /* is child dead? */
    struct list fd_table;
    struct list file_mapped;
    struct dir *dir;                /* current working directory */
  };

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
bool load_segment (struct page *spte, void *vaddr);
void init_load_lock ();

#endif /* userprog/process.h */
