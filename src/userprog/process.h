#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <lib/user/syscall.h>

#define STACK_SIZE (1<<23)
struct file_desc
  {
    int num;
    struct file *file;
    struct list_elem elem;
  };

struct map_file
  {
    mapid_t mid;
    void *addr;
    struct file *file;
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
    struct list mf_table;
  };

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
bool load_segment (struct page *spte, void *vaddr);

#endif /* userprog/process.h */
