#include "vm/swap.h"
#include "devices/block.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include <bitmap.h>
#include <stdio.h>
#define SECTOR_IN_PAGE 8 /* PGSIZE/BLOCK_SECTOR_SIZE */

struct lock swap_lock;
struct bitmap *swap_bitmap;
struct block *swap_block;

void
swap_init (void)
{
  /* Init SWAP_BITMAP and SWAP_LOCK and SWAP_BLOCK. */
  swap_block = block_get_role (BLOCK_SWAP);
  swap_bitmap = bitmap_create (block_size (swap_block) / SECTOR_IN_PAGE);
  if (swap_bitmap == NULL)
    return;
  /* Set bitmap's all bit to false. */
  bitmap_set_all(swap_bitmap,false);
  lock_init (&swap_lock);
}

void
swap_in (size_t used_index, void *kaddr)
{
  /* Read from disk at correspond to USED_INDEX
     and copy it to KADDR. */
  lock_acquire (&swap_lock);
  if(used_index == BITMAP_ERROR)
    {
      lock_release (&swap_lock);
      return;
    }

  int i;
  /* If bitmap's USED_INDEX location is free, fail. */
  if (bitmap_test (swap_bitmap, used_index) == false)
    {
      lock_release (&swap_lock);
      return;
    }
  /* Read from block(disk) page information.
     Each page consist of SECTOR_IN_PAGE(8) blocks. */
  for (i = 0; i < SECTOR_IN_PAGE; i++)
    block_read (swap_block, used_index * SECTOR_IN_PAGE + i, kaddr + BLOCK_SECTOR_SIZE* i);

  /* The physical page information is go out disk
     so set used_index location is free. */
  bitmap_set(swap_bitmap, used_index, false);
  lock_release (&swap_lock);
}

size_t 
swap_out (void *kaddr)
{
  lock_acquire (&swap_lock);
  int i;
  size_t index;
  /* Find free swap slot to first fit. And set bit opposite
     because it will be use. */
  index = bitmap_scan_and_flip (swap_bitmap, 0, 1, false);
  if(index == BITMAP_ERROR)
    {
      lock_release(&swap_lock);
      return BITMAP_ERROR;
    }
  /* Write to block(disk) page information. */
  for (i = 0; i < SECTOR_IN_PAGE; i++)
    block_write (swap_block, index * SECTOR_IN_PAGE + i, kaddr + BLOCK_SECTOR_SIZE * i);
  lock_release (&swap_lock);
  return index;
}
