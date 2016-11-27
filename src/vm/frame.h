#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <list.h>
#include "thread/sync.h"

struct frame_entry
  {
    void *frame;
    tid_t tid;
    void *uaddr;
    struct lock lock;         /* Mutual exclusion */
    struct list_elem elem;    /* allocate */
  };

void init_frame_table (void);
void* insert_frame_entry (tid_t tid, void *uaddr);

#endif
