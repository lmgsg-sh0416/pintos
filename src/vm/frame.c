#include <list.h>
#include "vm/frame.h"
#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"

static struct list frame_table;

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
      if (pagedir_is_accessed (f->pd, f->uaddr))
        {
          pagedir_set_accessed (f->pd, f->uaddr, false);
          list_push_back (&frame_table, &(f->elem));
        }
      else
        {
          success = allocate_swap_slot (f->pd, f->uaddr, f->frame);
          if (!success)
            return NULL;
          pagedir_clear_page (f->pd, f->uaddr);
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
}

void*
insert_frame_entry (uint32_t *pd, void *uaddr)
{
  struct frame_entry *f;
  void *frame = palloc_get_page (PAL_USER);
  if (frame == NULL)
    {
      frame = evict ();
      ASSERT (frame != NULL);   // induce kernel panic when no one can be evicted
    }
  f = (struct frame_entry*) malloc (sizeof *f);
  f->frame = frame;
  f->pd = pd;
  f->uaddr = uaddr;
  lock_init (&(f->lock));
  list_push_back (&frame_table, &(f->elem));
  return frame;
}
