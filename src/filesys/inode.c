#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/cache.h"
#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define INVALID_SECTOR 100000

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
    block_sector_t direct[124];
    block_sector_t single_indirect;
    block_sector_t double_indirect;
  }; // Total: 4 * 128 = 512 bytes

struct indirect_block
  {
    block_sector_t ptrs[128];
  }; // Total: 4 * 128 = 512 bytes

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */
  };

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);
  if (pos < inode->data.length)
    {
      block_sector_t sector = pos / BLOCK_SECTOR_SIZE;
      if (sector < 124)
        {
          return inode->data.direct[sector];
        }
      else if (sector < 252) // 124 + 128
        {
          struct indirect_block first;
          //cache_read (inode->data.single_indirect, &first);
          block_read (fs_device, inode->data.single_indirect, &first);
          return first.ptrs[sector - 124];
        }
      else if (sector < 16384) // LIMIT: 8 MB
        {
          struct indirect_block first, second;
          block_sector_t sectors_left = sector - 252;

          block_read (fs_device, inode->data.double_indirect, &first);
          block_read (fs_device, first.ptrs[sectors_left / 128], &second);
          //cache_read (inode->data.double_indirect, &first);
          //cache_read (first.ptrs[sectors_left / 128], &second);
          return second.ptrs[sectors_left % 128];
        }
      else
        return -1;
      //return inode->data.start + pos / BLOCK_SECTOR_SIZE;
    }
  else
    return -1;
}

/* Grow the length of the inode to given length. */
static void
inode_grow (struct inode_disk *disk_inode, block_sector_t sector, off_t length)
{
  static char zeros[BLOCK_SECTOR_SIZE];
  block_sector_t sectors_now = bytes_to_sectors (disk_inode->length);
  off_t length_left = length - ROUND_UP (disk_inode->length, BLOCK_SECTOR_SIZE);

  if (length_left <= 0)
    disk_inode->length = length;
  else if (length_left > 0)
    disk_inode->length = ROUND_UP (disk_inode->length, BLOCK_SECTOR_SIZE);

  while (length_left > 0)
    {
      size_t grown = length_left > BLOCK_SECTOR_SIZE ? BLOCK_SECTOR_SIZE : length_left;
      struct indirect_block first, second;
      block_sector_t *allocated;
      
      if (sectors_now < 124)
        allocated = &disk_inode->direct[sectors_now];
      else if (sectors_now < 252)
        {
          if (disk_inode->single_indirect == INVALID_SECTOR)
            {
              size_t i;

              if (!free_map_allocate (1, &disk_inode->single_indirect))
                return;

              block_read (fs_device, disk_inode->single_indirect, &first);
              for (i = 0; i < 128; i++)
                first.ptrs[i] = INVALID_SECTOR;
              block_write (fs_device, disk_inode->single_indirect, &first);
            }
          else
            block_read (fs_device, disk_inode->single_indirect, &first);

          allocated = &first.ptrs[sectors_now - 124];
        }
      else if (sectors_now < 16384)
        {
          if (disk_inode->double_indirect == INVALID_SECTOR)
            {
              size_t i;

              if (!free_map_allocate (1, &disk_inode->double_indirect))
                return;

              block_read (fs_device, disk_inode->double_indirect, &first);
              for (i = 0; i < 128; i++)
                first.ptrs[i] = INVALID_SECTOR;
              block_write (fs_device, disk_inode->double_indirect, &first);
            }
          else
            block_read (fs_device, disk_inode->double_indirect, &first);

          if (first.ptrs[(sectors_now - 252) / 128] == INVALID_SECTOR)
            {
              size_t i;
              if (!free_map_allocate (1, &first.ptrs[(sectors_now - 252) / 128]))
                return;

              block_read (fs_device, first.ptrs[(sectors_now - 252) / 128], &second);
              for (i = 0; i < 128; i++)
                second.ptrs[i] = INVALID_SECTOR;
              block_write (fs_device, first.ptrs[(sectors_now - 252) / 128], &second);
            }
          else
            block_read (fs_device, first.ptrs[(sectors_now - 252) / 128], &second);

          allocated = &second.ptrs[(sectors_now - 252) % 128];
        }
      else
        return;
      
      if (!free_map_allocate (1, allocated))
        return;

      block_write (fs_device, *allocated, zeros);
      //cache_write (*allocated, zeros);

      if (sectors_now < 124)
        {
          block_write (fs_device, sector, disk_inode);
        }
      else if (sectors_now < 252)
        {
          block_write (fs_device, disk_inode->single_indirect, &first);
          block_write (fs_device, sector, disk_inode);
        }
      else if (sectors_now < 16384)
        {
          block_write (fs_device, first.ptrs[(sectors_now - 252) / 128], &second);
          block_write (fs_device, disk_inode->double_indirect, &first);
          block_write (fs_device, sector, disk_inode); 
        }
      else
        return ;

      sectors_now++;
      length_left -= grown;
      disk_inode->length += grown;
    }

  if (length_left < 0)
    disk_inode->length = length;

  return;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;
static struct lock inode_lock;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
  lock_init (&inode_lock);
}
/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      size_t i;

      disk_inode->length = 0;
      disk_inode->magic = INODE_MAGIC;
      disk_inode->single_indirect = INVALID_SECTOR;
      disk_inode->double_indirect = INVALID_SECTOR;
      for (i = 0; i < 124; i++)
        disk_inode->direct[i] = INVALID_SECTOR;

      inode_grow (disk_inode, sector, length);

      block_write (fs_device, sector, disk_inode);
      success = true;

      free (disk_inode);
    }
//
//  if (disk_inode != NULL)
//    {
//      size_t sectors = bytes_to_sectors (length);
//      disk_inode->length = length;
//      disk_inode->magic = INODE_MAGIC;
//      if (free_map_allocate (sectors, &disk_inode->start)) 
//        {
//          block_write (fs_device, sector, disk_inode);
//          if (sectors > 0) 
//            {
//              static char zeros[BLOCK_SECTOR_SIZE];
//              size_t i;
//              
//              for (i = 0; i < sectors; i++) 
//                block_write (fs_device, disk_inode->start + i, zeros);
//            }
//          success = true; 
//        } 
//      free (disk_inode);
//    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  lock_acquire (&inode_lock);
  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode->open_cnt++;
          lock_release (&inode_lock);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
  {
    lock_release (&inode_lock);
    return NULL;
  }

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  cache_read (inode->sector, &inode->data);
  //block_read (fs_device, inode->sector, &inode->data);
  lock_release (&inode_lock);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  lock_acquire (&inode_lock);
  if (inode != NULL)
    inode->open_cnt++;
  lock_release (&inode_lock);
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  lock_acquire (&inode_lock);
  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          off_t sectors = (off_t) bytes_to_sectors (inode->data.length) - 1;

          while (sectors >= 252)
            {
              struct indirect_block first, second;
              
              block_read (fs_device, inode->data.double_indirect, &first);
              block_read (fs_device, first.ptrs[(sectors - 252) / 128], &second);

              while ((sectors - 252) % 128 != 0)
                {
                  free_map_release (second.ptrs[(sectors - 252) % 128], 1);
                  sectors--;
                }
              free_map_release (first.ptrs[(sectors - 252) / 128], 1);
              free_map_release (second.ptrs[sectors - 252], 1);
              sectors--;

              if (sectors == 251)
                free_map_release (inode->data.double_indirect, 1);
            }
          
          while (sectors >= 124)
            {
              struct indirect_block first;

              block_read (fs_device, inode->data.single_indirect, &first);
              free_map_release (first.ptrs[sectors - 124], 1);
              sectors--;

              if (sectors == 123)
                free_map_release (inode->data.single_indirect, 1);
            }

          while (sectors >= 0)
            {
              free_map_release (inode->data.direct[sectors], 1);
              sectors--;
            }

          ASSERT (sectors < 0);
          free_map_release (inode->sector, 1);
//          free_map_release (inode->data.start,
//                            bytes_to_sectors (inode->data.length)); 
        }

      free (inode); 
    }
  lock_release (&inode_lock);
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  lock_acquire (&inode_lock);
  inode->removed = true;
  lock_release (&inode_lock);
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);

      if (sector_idx == INVALID_SECTOR)
        return bytes_read;

      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          cache_read (sector_idx, buffer + bytes_read);
        }
      else 
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          cache_read (sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  if (inode->data.length < offset + size)
    {
      inode_grow (&inode->data, inode->sector, offset + size);
      block_write (fs_device, inode->sector, &inode->data);
    }

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          cache_write (sector_idx, buffer + bytes_written);
        }
      else 
        {
          /* We need a bounce buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left) 
            cache_read (sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          cache_write (sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}
