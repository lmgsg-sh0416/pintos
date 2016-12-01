#include "filesys/cache.h"
#include "devices/timer.h"
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
//  uint32_t num_pages = buffer_cache_size / PGSIZE;
//
//  if (buffer_cache_size % PGSIZE != 0)
//    num_pages++;

  cache_pool = malloc (buffer_cache_size);

  list_init (&buffer_cache);
  lock_init (&cache_lock);
  num_cache = 0;

  thread_create ("periodic_flush", PRI_MIN, periodic_flush, NULL);
}

uint8_t *
get_buffer_cache (block_sector_t sector, bool is_write)
{
  struct cache *entry = NULL;
  block_sector_t *aux = NULL;

  lock_acquire (&cache_lock);
  entry = fetch_buffer_cache (sector);
  lock_release (&cache_lock);

  ASSERT (entry != NULL);

  if (is_write)
    entry->dirty = true;
  else 
    {
      aux = malloc (sizeof *aux);
      *aux = sector + 1;
      thread_create ("read-ahead", PRI_MIN, read_ahead, aux);
    }

  lock_acquire (&cache_lock);
  list_remove (&entry->elem);
  list_push_back (&buffer_cache, &entry->elem);
  lock_release (&cache_lock);

  return entry->data;
}

void
flush_buffer_cache ()
{
  size_t i;

  if (num_cache == 0)
    {
      return;
    }

  lock_acquire (&cache_lock);
  for (i = 0; i < CACHE_SIZE_LIMIT; i++)
    {
      struct cache *temp = &cache_pool[i];

      if (temp->dirty)
        {
          block_write (fs_device, temp->sector, temp->data);
          temp->dirty = false;
        }
    }
  lock_release (&cache_lock);
}

static bool
search_buffer_cache (block_sector_t sector, struct cache **entry)
{
  size_t i;

  if (num_cache == 0)
    {
      *entry = NULL;
      return false;
    }

  for (i = 0; i < CACHE_SIZE_LIMIT; i++)
    {
      struct cache *temp = &cache_pool[i];

      if (temp->sector == sector)
        {
          *entry = temp;
          return true;
        }
      
      if (i == num_cache - 1)
        break;
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
        ASSERT (!list_empty (&buffer_cache));
  
        struct cache *evicted = list_entry (list_front (&buffer_cache), struct cache, elem);
  
        if (evicted->dirty)
          block_write (fs_device, evicted->sector, evicted->data);
        
        list_remove (&evicted->elem);
        entry = evicted;
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
