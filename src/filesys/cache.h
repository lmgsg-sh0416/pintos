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
  
//    struct lock cache_lock;

    struct list_elem elem;
  };

// Ver. 2
//struct cache 
//  {
//    block_sector_t sector;
//
//    uint8_t data[BLOCK_SECTOR_SIZE];
//    bool used;
//    bool dirty;
//
//    struct lock cache_lock;
//    struct list_elem elem;
//  };

// search_buffer_cache (block_sector_t sector, struct cache *entry);
void init_buffer_cache (void);
uint8_t* get_buffer_cache (block_sector_t sector, bool is_write);
void flush_buffer_cacahe (void);
//uint8_t* read_buffer_cache (block_sector_t sector);
//uint8_t* write_buffer_cache (block_sector_t sector);
//void read_buffer_cache (block_sector_t sector, uint8_t *buffer,
//                        off_t bytes_read, int sector_ofs, int chunk_size);
//void write_buffer_cache (block_sector_t sector, const uint8_t *buffer,
//                         off_t bytes_written, int sector_ofs, int chunk_size);
void flush_buffer_cache (void);
//void free_buffer_cache (void);

#endif
