#include "filesys/cache.h"
#include <string.h>
#include "devices/timer.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"

static struct cache *cache_pool;

static bool search_buffer_cache (block_sector_t sector, struct cache **entry);
static struct cache* fetch_buffer_cache (block_sector_t sector);
static void periodic_flush (void *aux);
static void read_ahead (void *aux);

static struct list buffer_cache;
static struct lock cache_lock;
static size_t num_cache;

void
init_buffer_cache ()
{
  uint32_t buffer_cache_size = CACHE_SIZE_LIMIT * sizeof (struct cache);
  cache_pool = malloc (buffer_cache_size);

  list_init (&buffer_cache);
  lock_init (&cache_lock);
  num_cache = 0;

  thread_create ("periodic_flush", PRI_MIN, periodic_flush, NULL);
}

void
cache_read (block_sector_t sector, void *buffer)
{
  struct cache *entry = NULL;
  block_sector_t *aux = NULL;

  lock_acquire (&cache_lock);

  entry = fetch_buffer_cache (sector);
  ASSERT (entry != NULL);

  memcpy (buffer, entry->data, BLOCK_SECTOR_SIZE);

  /* addition read process */
  aux = malloc (sizeof *aux);
  *aux = sector + 1;
  thread_create ("read-ahead", PRI_MIN, read_ahead, aux);

  list_remove (&entry->elem);
  list_push_back (&buffer_cache, &entry->elem);
  
  lock_release (&cache_lock);
}

void
cache_write (block_sector_t sector, const void *buffer)
{
  struct cache *entry = NULL;

  lock_acquire (&cache_lock);

  entry = fetch_buffer_cache (sector);
  ASSERT (entry != NULL);
  
  memcpy (entry->data, buffer, BLOCK_SECTOR_SIZE);

  /* addition write process */
  entry->dirty = true;

  list_remove (&entry->elem);
  list_push_back (&buffer_cache, &entry->elem);
  
  lock_release (&cache_lock);
}

void
flush_buffer_cache ()
{
  lock_acquire (&cache_lock);
  if (list_empty (&buffer_cache))
    {
      lock_release (&cache_lock);
      return;
    }
  else
    {
      struct list_elem *e;
      for (e = list_begin (&buffer_cache); e != list_end (&buffer_cache);
           e = list_next (e))
        {
          struct cache *temp = list_entry (e, struct cache, elem);
          if (temp->dirty)
            {
              block_write (fs_device, temp->sector, temp->data);
              temp->dirty = false;
            }
        }
    }
  lock_release (&cache_lock);
}

static bool
search_buffer_cache (block_sector_t sector, struct cache **entry)
{
  if (list_empty (&buffer_cache))
    {
      *entry = NULL;
      return false;
    }
  else
    {
      struct list_elem *e;
      for (e = list_begin (&buffer_cache); e != list_end (&buffer_cache);
           e = list_next (e))
        {
          struct cache *temp = list_entry (e, struct cache, elem);
          if (temp->sector == sector)
            {
              *entry = temp;
              return true;
            }
        }
      *entry = NULL;
      return false;
    }
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
            block_write (fs_device, evicted->sector, evicted->data);
          
          list_remove (&evicted->elem);
          entry = evicted;
        }
      else
        {
          entry = &cache_pool[num_cache++];
        }

      entry->sector = sector;
      entry->dirty = false;
      
      block_read (fs_device, entry->sector, entry->data);
      list_push_back (&buffer_cache, &entry->elem);
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
