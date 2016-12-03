#include "filesys/cache.h"
#include <string.h>
#include "devices/timer.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "filesys/filesys.h"

static struct cache *cache_pool;
static struct list buffer_cache;
static struct lock cache_lock;
static size_t num_cache;

static bool
search_buffer_cache (block_sector_t sector, struct cache **entry)
{
  if (num_cache == 0)
    {
      *entry = NULL;
      return false;
    }
  else
    {
      size_t i;
      for (i = 0; i < num_cache; i++)
        {
          struct cache *temp = &cache_pool[i];
          if (temp->sector == sector)
            {
              *entry = temp;
              return true;
            }
        }
    }
  *entry = NULL;
  return false;
}

static struct cache *
fetch_buffer_cache (block_sector_t sector)
{
  struct cache *entry = NULL;

  if (!search_buffer_cache (sector, &entry))
    {
      if (num_cache == CACHE_SIZE_LIMIT)
        {
          struct cache *evicted = list_entry (list_front (&buffer_cache), struct cache, elem);
          if (evicted->dirty)
            {
              block_write (fs_device, evicted->sector, evicted->data);
              evicted->dirty = false;
            }

          entry = evicted;
          list_remove (&entry->elem);
          num_cache--;
        }
      else
        entry = &cache_pool[num_cache];

      entry->sector = sector;
      entry->dirty = false;

      block_read (fs_device, entry->sector, entry->data);
      list_push_back (&buffer_cache, &entry->elem);
      num_cache++;
    }

  return entry;
}

static void
periodic_flush (void *aux UNUSED)
{
  for ( ; ; )
    {
      timer_sleep (FLUSH_FREQ);
      flush_buffer_cache ();
    }
}

static void
read_ahead (void *aux)
{
  lock_acquire (&cache_lock);
  fetch_buffer_cache (*(block_sector_t *)aux);
  lock_release (&cache_lock);
  free (aux);
}

void
init_buffer_cache ()
{
  size_t i;
  uint32_t buffer_cache_size = CACHE_SIZE_LIMIT * sizeof (struct cache);
  size_t num = buffer_cache_size / PGSIZE;
  if (buffer_cache_size % PGSIZE)
    num++;

  cache_pool = palloc_get_multiple (PAL_USER | PAL_ZERO, num);

  for (i = 0; i < CACHE_SIZE_LIMIT; i++)
    cache_pool[i].dirty = false;

  list_init (&buffer_cache);
  lock_init (&cache_lock);
  num_cache = 0;

  thread_create ("periodic_flush", PRI_MIN, periodic_flush, NULL);
}

void
cache_read (block_sector_t sector, void *buffer)
{
  struct cache *entry;
  block_sector_t *aux;

  lock_acquire (&cache_lock);

  entry = fetch_buffer_cache (sector);
  memcpy (buffer, entry->data, BLOCK_SECTOR_SIZE);

  list_remove (&entry->elem);
  list_push_back (&buffer_cache, &entry->elem);

  ASSERT (list_size (&buffer_cache) == num_cache);

  lock_release (&cache_lock);

//  aux = malloc (sizeof *aux);
//  if (aux != NULL)
//    {
//      *aux = sector + 1;
//      thread_create ("read-ahead", PRI_MIN, read_ahead, aux);
//    }
}

void
cache_write (block_sector_t sector, const void *buffer)
{
  struct cache *entry;

  lock_acquire (&cache_lock);

  entry = fetch_buffer_cache (sector);
  memcpy (entry->data, buffer, BLOCK_SECTOR_SIZE);
  entry->dirty = true;

  list_remove (&entry->elem);
  list_push_back (&buffer_cache, &entry->elem);

  ASSERT (list_size (&buffer_cache) == num_cache);

  lock_release (&cache_lock);
}

void
flush_buffer_cache ()
{
  lock_acquire (&cache_lock);
  if (num_cache == 0)
    {
      lock_release (&cache_lock);
      return;
    }
  else
    {
      size_t i;
      for (i = 0; i < num_cache; i++)
        {
          struct cache *temp = &cache_pool[i];
          if (temp->dirty)
            {
              block_write (fs_device, temp->sector, temp->data);
              temp->dirty = false;
            }
        }
    }
  lock_release (&cache_lock);
}
