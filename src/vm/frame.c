#include "vm/page.h"
#include "vm/swap.h"
#include "vm/frame.h"
#include <list.h>
#include <stdio.h>
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"

static struct list lru_list;
static struct lock lru_list_lock;
static struct list_elem *lru_clock;

void
lru_list_init (void)
{
  /* Init LRU_LIST and LRU_LIST_LOCK.
     Also set LRU_CLOCK to NULL. */
  list_init (&lru_list);
  lock_init (&lru_list_lock);
  lru_clock = NULL;
}

void
add_page_to_lru_list (struct page *page)
{
  /* Insert page to LRU_LIST. */
  lock_acquire (&lru_list_lock);
  list_push_back (&lru_list, &page->lru);
  lock_release (&lru_list_lock);
}

void
del_page_from_lru_list (struct page *page)
{
  /* Delete page from LRU_LIST and
     set clock to next page. */
  if (lru_clock == &page->lru)
    lru_clock = list_next (lru_clock);
  list_remove (&page->lru);
}

struct page *
alloc_page (enum palloc_flags flags)
{
  /* Allocate page and add into LRU_LIST. */
  struct page *page;
  page = malloc (sizeof (struct page));
  if (page == NULL)
    return NULL;

  page->kaddr = palloc_get_page (flags);
  /* If there isn't enough memory try to
     swap and free page using clock algorithm. */
  while (page->kaddr == NULL)
    {
      try_to_free_pages ();
      page->kaddr = palloc_get_page (flags);
    }
  page->thread = thread_current ();
  add_page_to_lru_list (page);
  return page;
}

void
free_page (void *kaddr)
{
  /* Free page using KADDR. Call __free_page()
     to free page and delete from LRU_LIST. */
  lock_acquire (&lru_list_lock);
  struct list_elem *e;
  struct page *p;
  for (e = list_begin (&lru_list); e != list_end (&lru_list); e = list_next (e))
    {
      p = list_entry (e, struct page, lru);
      if (p->kaddr == kaddr)
        {
          __free_page (p);
          break;
        }
    }
  lock_release (&lru_list_lock);
}

void
__free_page (struct page *page)
{
  /* free page and delete from LRU_LIST. */
  del_page_from_lru_list (page);
  pagedir_clear_page (page->thread->pagedir, page->vme->vaddr);
  palloc_free_page (page->kaddr);
  free (page);
}

static struct list_elem *
get_next_lru_clock (void)
{
  if (list_empty(&lru_list))
    return NULL;
  /* Return next page in LRU_LIST. LRU_CLOCK
     will point that page. */
  if (lru_clock == NULL || lru_clock == list_end (&lru_list))
    lru_clock = list_begin (&lru_list);

  lru_clock = list_next (lru_clock);

  if (lru_clock == list_end (&lru_list))
    return get_next_lru_clock ();
  return lru_clock;
}

void
try_to_free_pages (void)
{
  /* When physical memory is full, do swapping. */
  lock_acquire (&lru_list_lock);
  struct page *p;
  /* If accessed bit is 1 set accessed bit to 0. And keep search
     LRU_LIST to find dirty bit is 0. Please note pinning
     page don't be victim. */
  p = list_entry (get_next_lru_clock (), struct page, lru);
  while (pagedir_is_accessed (p->thread->pagedir, p->vme->vaddr) || p->vme->pinned)
    {
      pagedir_set_accessed (p->thread->pagedir, p->vme->vaddr, false);
      p = list_entry (get_next_lru_clock (), struct page, lru);
    }
  /* If victim page's type is VM_BIN to swap_out()
     and set type VM_ANON. If VM_FILE and dirty bit
     is 1, record change of file information to disk.
     If VM_ANON, do swap_out(). */
  switch (p->vme->type)
    {
      case VM_BIN:
        if (pagedir_is_dirty (p->thread->pagedir, p->vme->vaddr))
          {
            p->vme->swap_slot = swap_out (p->kaddr);
            p->vme->type = VM_ANON;
          }
        break;
      case VM_FILE:
        if (pagedir_is_dirty (p->thread->pagedir, p->vme->vaddr))
          {
            lock_acquire (&filesys_lock);
            file_write_at (p->vme->file, p->kaddr, p->vme->read_bytes, p->vme->offset);
            lock_release (&filesys_lock);
          }
        break;
      case VM_ANON:
        p->vme->swap_slot = swap_out (p->kaddr);
        break;
    }
  /* The physical page is in disk (not in memory)
     set IS_LOADED is false. */
  p->vme->is_loaded = false;
  __free_page (p);
  lock_release (&lru_list_lock);
}
