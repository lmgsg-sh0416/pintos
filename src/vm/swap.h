#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "devices/block.h"
#include "threads/sync.h"
#include <list.h>

struct swap_entry
  {
    struct lock lock;
    struct list_elem elem;
    block_sector_t sector;    /* offset of block */
    tid_t t;                  /* tid */
    void *uaddr;              /* uaddr */
  };

void init_swap_table ();
void free_swap_slot_by_address (tid_t t, void *uaddr);  /* when reload */
void free_swap_slot_by_tid (tid_t t);                   /* when terminate */
bool allocate_swap_slot (tid_t t, void *uaddr);         /* when evict */

#endif /* vm/swap.h */
