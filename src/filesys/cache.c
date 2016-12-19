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
  lock_acquire (&cache_lock);
  if (num_cache == 0)
    {
      *entry = NULL;
      lock_release (&cache_lock);
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
              lock_acquire (&temp->cache_lock);
              lock_release (&cache_lock);
              return true;
            }
        }
    }
  *entry = NULL;
  lock_release (&cache_lock);
  return false;
}

static struct cache *
fetch_buffer_cache (block_sector_t sector)
{
  struct cache *entry = NULL;

  if (!search_buffer_cache (sector, &entry))
    {
      lock_acquire (&cache_lock);
      if (num_cache == CACHE_SIZE_LIMIT)
        {
          struct list_elem *e;
          struct cache *evicted;
          for (e = list_begin (&buffer_cache); e != list_end (&buffer_cache);
               e = list_next (e))
            {
              evicted = list_entry (e, struct cache, elem);
              if (lock_try_acquire (&evicted->cache_lock))
                break;
            }
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
        {
          entry = &cache_pool[num_cache];
          lock_acquire (&entry->cache_lock);
        }

      entry->sector = sector;
      entry->dirty = false;

      block_read (fs_device, entry->sector, entry->data);
      list_push_back (&buffer_cache, &entry->elem);
      num_cache++;
      lock_release (&cache_lock);
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
    {
      cache_pool[i].dirty = false;
      lock_init (&(cache_pool[i].cache_lock));
    }

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

  entry = fetch_buffer_cache (sector);
  memcpy (buffer, entry->data, BLOCK_SECTOR_SIZE);

  list_remove (&entry->elem);
  list_push_back (&buffer_cache, &entry->elem);

  ASSERT (list_size (&buffer_cache) == num_cache);
  lock_release (&entry->cache_lock);

//  aux = malloc (sizeof *aux);
//  if (aux != NULL)
//    {
//      *aux = (sector + 1) % block_size (fs_device);
//      thread_create ("read-ahead", PRI_MIN, read_ahead, aux);
//    }
}

void
cache_write (block_sector_t sector, const void *buffer)
{
  struct cache *entry;

  entry = fetch_buffer_cache (sector);
  memcpy (entry->data, buffer, BLOCK_SECTOR_SIZE);
  entry->dirty = true;

  list_remove (&entry->elem);
  list_push_back (&buffer_cache, &entry->elem);
  ASSERT (list_size (&buffer_cache) == num_cache);
  lock_release (&entry->cache_lock);
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
