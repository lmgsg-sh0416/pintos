#include "vm/swap.h"
#include "devices/block.h"
#include "threads/malloc.h"

static struct list swap_table;

void
init_swap_table ()
{
  list_init (&swap_table);
}

void
free_swap_slot_by_address (tid_t t, void *uaddr)
{

}

void
free_swap_slot_by_tid (tid_t t)
{

}

bool
allocate_swap_slot (tid_t t, void *uaddr)
{
  struct block *b = block_get_role (BLOCK_SWAP);
  struct swap_entry *p;
  if (b == NULL)
    return false;
  p = (struct swap_entry) malloc (sizeof *p);
  lock_init (&p->lock);
  p->b = b;
  p->t = t;
  p->uaddr = uaddr;
  list_

}
