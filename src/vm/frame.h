#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <list.h>
#include "threads/synch.h"
#include "vm/swap.h"

struct frame_entry
  {
    void *frame;              /* kernel virtual address */
    uint32_t *pd;             /* page directory */
    void *uaddr;              /* uaddr */
    struct lock lock;         /* Mutual exclusion */
    struct list_elem elem;
  };

void init_frame_table (void);
void* insert_frame_entry (uint32_t *pd, void *uaddr);

#endif
