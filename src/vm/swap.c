#include "vm/swap.h"
#include "devices/block.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include <bitmap.h>

#define SWAP_SECTOR_SIZE (PGSIZE/BLOCK_SECTOR_SIZE)

static struct list swap_table;
static struct bitmap *swap_bitmap;

static struct block *b;

void
init_swap_table ()
{
  list_init (&swap_table);
  b = block_get_role (BLOCK_SWAP);
  swap_bitmap = bitmap_create (block_size (b) / SWAP_SECTOR_SIZE);
}

void
free_swap_slot_by_address (uint32_t *pd, void *upage, void *frame)
{
  struct list_elem *e;
  struct swap_entry *s;
  block_sector_t j;
  // find swap slot
  for (e = list_begin (&swap_table); e != list_end (&swap_table);
       e = list_next (e))
    {
      s = list_entry (e, struct swap_entry, elem);
      if (s->pd == pd && s->upage == upage)
        break;
    }
  // case: no swap slot
  if (e == list_end (&swap_table))
    return;
  // read from swap sector to page
  for (j=0; j<SWAP_SECTOR_SIZE; j++)
    {
      block_read (b, 8*(s->sector)+j, frame);
      frame += BLOCK_SECTOR_SIZE;
    }
  // unmark bitmap
  bitmap_set (swap_bitmap, s->sector, false);
  // insert swap_entry into swap_table
  list_remove (&(s->elem));
  free (s);
}

void
free_swap_slot_by_pd (uint32_t *pd)
{
  struct list_elem *e;
  struct swap_entry *s;
  // find swap slot
  for (e = list_begin (&swap_table); e != list_end (&swap_table);
       e = list_next (e))
    {
      s = list_entry (e, struct swap_entry, elem);
      if (s->pd == pd)
        {
          // unmark bitmap
          bitmap_set (swap_bitmap, s->sector, false);
          // remove swap_entry into swap_table
          list_remove (&(s->elem));
          free (s);
        }
    }
}

bool
allocate_swap_slot (uint32_t *pd, void *upage, void *frame)
{
  struct swap_entry *s;
  size_t i, swap_bitmap_size;
  block_sector_t j;

  // find swap sector
  swap_bitmap_size = bitmap_size (swap_bitmap);
  for (i=0; i<swap_bitmap_size; i++)
    if (bitmap_test (swap_bitmap, i))
      break;
  // case: no swap sector
  if (i==swap_bitmap_size)
    return false;
  // write from page to swap sector
  for (j=0; j<SWAP_SECTOR_SIZE; j++)
    {
      block_write (b, 8*i+j, frame);
      frame += BLOCK_SECTOR_SIZE;
    }
  // mark bitmap
  bitmap_set (swap_bitmap, i, true);
  // insert swap_entry into swap_table
  s = (struct swap_entry*) malloc (sizeof *s);
  s->sector = i;
  s->pd = pd;
  s->upage = upage;
  lock_init (&s->lock);
  list_push_back (&swap_table, &(s->elem));
}
