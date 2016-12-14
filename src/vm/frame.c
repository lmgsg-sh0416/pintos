#include <list.h>
#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"

static struct frame_entry *frame_table;
static uint32_t frame_head;
static uint32_t frame_entry_num;
static struct lock frame_lock;

/* return null if eviction fail */
static void*
evict (enum palloc_flags flags)
{
  void *p;
  bool success;
  while (true)
    {
      // clock algorithm
      if (frame_table[frame_head].valid == false)
        frame_head = (frame_head + 1) % frame_entry_num;
      else if (frame_table[frame_head].pinned)
        frame_head = (frame_head + 1) % frame_entry_num;
      else if (pagedir_is_accessed (frame_table[frame_head].pd, frame_table[frame_head].upage))
        {
          pagedir_set_accessed (frame_table[frame_head].pd, frame_table[frame_head].upage, false);
          frame_head = (frame_head + 1) % frame_entry_num;
        }
      else
        {
          success = allocate_swap_slot (frame_table[frame_head].pd, frame_table[frame_head].upage, frame_table[frame_head].frame);
          if (!success)
            return NULL;
          frame_table[frame_head].valid = false;
          pagedir_clear_page (frame_table[frame_head].pd, frame_table[frame_head].upage);
          p = frame_table[frame_head].frame;
          if (flags & PAL_ZERO)
            memset (p, 0, PGSIZE);
          return p;
        }
    }
  return NULL;
}

void
init_frame_table (uint32_t ram_size)
{
  uint32_t frame_table_size;
  frame_entry_num = ram_size/4;
  frame_table_size = frame_entry_num * sizeof (struct frame_entry);
  frame_table = palloc_get_multiple (PAL_ASSERT | PAL_USER | PAL_ZERO, frame_table_size/PGSIZE);
  frame_head = 0;
  lock_init (&frame_lock);
}

/* CAUTION: frame is pinned when created */
void*
insert_frame_entry (uint32_t *pd, void *upage, enum palloc_flags flags)
{
  void *frame;
  lock_acquire (&frame_lock);
  frame = palloc_get_page (flags);
  if (frame == NULL)
    {
      frame = evict (flags);
      ASSERT (frame != NULL);   // induce kernel panic when no one can be evicted
    }
  while (frame_table[frame_head].valid != false)
    frame_head = (frame_head + 1) % frame_entry_num;
  frame_table[frame_head].valid = true;
  frame_table[frame_head].frame = frame;
  frame_table[frame_head].pd = pd;
  frame_table[frame_head].upage = upage;
  frame_table[frame_head].pinned = 1;
  frame_head = (frame_head + 1) % frame_entry_num;

  lock_release (&frame_lock);
  return frame;
}

void
remove_frame_entry (uint32_t *pd, void *upage)
{
  lock_acquire (&frame_lock);
  while (true)
  {
    if (frame_table[frame_head].valid == true && frame_table[frame_head].pd == pd && frame_table[frame_head].upage == upage)
      break;
    frame_head = (frame_head + 1) % frame_entry_num;
  }
  palloc_free_page (frame_table[frame_head].frame);
  frame_table[frame_head].valid = false;
  lock_release (&frame_lock);
}

void
pin_frame (uint32_t *pd, void *uaddr)
{
  void *upage = pg_round_down (uaddr);
  int i;
  lock_acquire (&frame_lock);
  for (i=0;i<frame_entry_num;i++)
  {
    if (frame_table[i].valid == true && frame_table[i].pd == pd && frame_table[i].upage == upage)
      break;
  }
  if (i != frame_entry_num)
    frame_table[i].pinned++;
  lock_release (&frame_lock);
}

void
unpin_frame (uint32_t *pd, void *uaddr)
{
  void *upage = pg_round_down (uaddr);
  int i;
  lock_acquire (&frame_lock);
  for (i=0;i<frame_entry_num;i++)
  {
    if (frame_table[i].valid == true && frame_table[i].pd == pd && frame_table[i].upage == upage)
      break;
  }
  if (i != frame_entry_num)
    frame_table[i].pinned--;
  lock_release (&frame_lock);
}

