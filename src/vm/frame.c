#include <list.h>
#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"

static struct list frame_table;
static struct lock frame_lock;

/* return null if eviction fail */
static void*
evict (enum palloc_flags flags)
{
  struct list_elem *e;
  struct frame_entry *f;
  void *p;
  bool success;
  while (true)
    {
      e = list_pop_front (&frame_table);
      f = list_entry (e, struct frame_entry, elem);
      // clock algorithm
      if (f->pinned)
        {
          list_push_back (&frame_table, &(f->elem));
        }
      else if (pagedir_is_accessed (f->pd, f->upage))
        {
          pagedir_set_accessed (f->pd, f->upage, false);
          list_push_back (&frame_table, &(f->elem));
        }
      else
        {
          success = allocate_swap_slot (f->pd, f->upage, f->frame);
          if (!success)
            return NULL;
          pagedir_clear_page (f->pd, f->upage);
          p = f->frame;
          if (flags & PAL_ZERO)
            memset (p, 0, PGSIZE);
          list_remove (&(f->elem));
          free (f);
          return p;
        }
    }
  return NULL;
}

void
init_frame_table (void)
{
  list_init (&frame_table);
  lock_init (&frame_lock);
}

/* CAUTION: frame is pinned when created */
void*
insert_frame_entry (uint32_t *pd, void *upage, enum palloc_flags flags)
{
  struct frame_entry *f;
  void *frame;
  lock_acquire (&frame_lock);
  frame = palloc_get_page (flags);
  if (frame == NULL)
    {
      frame = evict (flags);
      ASSERT (frame != NULL);   // induce kernel panic when no one can be evicted
    }
  f = (struct frame_entry*) malloc (sizeof *f);
  f->frame = frame;
  f->pd = pd;
  f->upage = upage;
  f->pinned = 1;
  list_push_back (&frame_table, &(f->elem));
  lock_release (&frame_lock);
  return frame;
}

void
remove_frame_entry (uint32_t *pd, void *upage)
{
  struct frame_entry *f;
  struct list_elem *e;
  lock_acquire (&frame_lock);
  for (e = list_begin(&frame_table); e != list_end (&frame_table);
       e = list_next (e))
    {
      f = list_entry (e, struct frame_entry, elem);
      if (f->pd == pd && f->upage == upage)
        break;
    }
  ASSERT (e != list_end (&frame_table));
  palloc_free_page (f->frame);
  list_remove (&(f->elem));
  free (f);
  lock_release (&frame_lock);
}

void
pin_frame (uint32_t *pd, void *uaddr)
{
  struct frame_entry *f;
  struct list_elem *e;
  void *upage = pg_round_down (uaddr);
  lock_acquire (&frame_lock);
  for (e = list_begin(&frame_table); e != list_end (&frame_table);
       e = list_next (e))
    {
      f = list_entry (e, struct frame_entry, elem);
      if (f->pd == pd && f->upage == upage)
        break;
    }
  if (e != list_end (&frame_table))
    {
      f->pinned++;
    }
  lock_release (&frame_lock);
}

void
unpin_frame (uint32_t *pd, void *uaddr)
{
  struct frame_entry *f;
  struct list_elem *e;
  void *upage = pg_round_down (uaddr);
  lock_acquire (&frame_lock);
  for (e = list_begin(&frame_table); e != list_end (&frame_table);
       e = list_next (e))
    {
      f = list_entry (e, struct frame_entry, elem);
      if (f->pd == pd && f->upage == upage)
        break;
    }
  if (e != list_end (&frame_table))
    {
      f->pinned--;
    }
  lock_release (&frame_lock);
}

