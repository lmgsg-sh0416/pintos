#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include <stdbool.h>
#include <stdint.h>
#include <list.h>
#include "threads/synch.h"
#include "devices/block.h"
#include "filesys/off_t.h"

#define CACHE_SIZE_LIMIT 64
#define FLUSH_FREQ 10000

struct cache 
  {
    block_sector_t sector;
  
    uint8_t data[BLOCK_SECTOR_SIZE];
    bool dirty;
  
    struct lock cache_lock;
    struct list_elem elem;
  };

void init_buffer_cache (void);
void cache_read (block_sector_t sector, void *buffer);
void cache_write (block_sector_t sector, void *buffer);
void flush_buffer_cache (void);

#endif
