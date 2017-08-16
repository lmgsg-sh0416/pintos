#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <list.h>
#include "threads/synch.h"
#include "threads/palloc.h"
#include "vm/swap.h"

struct frame_entry
  {
    bool valid;
    void *frame;              /* kernel virtual address */
    uint32_t *pd;             /* page directory */
    void *upage;              /* uaddr */
    int pinned;               /* pin system */
  };

void init_frame_table (uint32_t ram_size);
void* insert_frame_entry (uint32_t *pd, void *upage, enum palloc_flags flags);
void remove_frame_entry (uint32_t *pd, void *upage);

#endif
