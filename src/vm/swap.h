#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <list.h>
#include "threads/synch.h"
#include "devices/block.h"

struct swap_entry
  {
    block_sector_t sector;    /* offset of block */
    uint32_t *pd;             /* page directory */
    void *upage;              /* upage */
    struct lock lock;         /* mutual exclusion */
    struct list_elem elem;
  };

void init_swap_table (void);
void free_swap_slot_by_address (uint32_t *pd, void *upage, void *frame);  /* when reload */
void free_swap_slot_by_pd (uint32_t *pd);                   /* when terminate */
bool allocate_swap_slot (uint32_t *pd, void *upage, void *frame);         /* when evict */

#endif /* vm/swap.h */
