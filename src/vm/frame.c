#include <list.h>
#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"

static struct list frame_table;
static struct lock frame_lock;

/* return null if eviction fail */
static void*
evict (void)
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
      if (pagedir_is_accessed (f->pd, f->upage))
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
          palloc_free_page (f->frame);
          p = palloc_get_page (PAL_USER);
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

void*
insert_frame_entry (uint32_t *pd, void *upage, enum palloc_flags flags)
{
  struct frame_entry *f;
  void *frame = palloc_get_page (flags);
  lock_acquire (&frame_lock);
  if (frame == NULL)
    {
      //frame = evict ();
      frame = NULL;
      ASSERT (frame != NULL);   // induce kernel panic when no one can be evicted
    }
  f = (struct frame_entry*) malloc (sizeof *f);
  f->frame = frame;
  f->pd = pd;
  f->upage = upage;
  lock_init (&(f->lock));
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
