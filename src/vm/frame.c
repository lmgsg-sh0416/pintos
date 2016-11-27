#include "vm/frame.h"
#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"

static struct list frame_table;

void
init_frame_table (void)
{
  list_init (&frame_table);
}

void*
insert_frame_entry (tid_t tid, void *uaddr)
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
  f->tid = tid;
  f->uaddr = uaddr;
  lock_init (&(f->lock));
  list_push_back (&frame_table, f->elem);
  return frame;
}

static void*
evict (void)
{
  return NULL;
}
