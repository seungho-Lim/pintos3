#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>

#define VM_BIN  0
#define VM_FILE 1
#define VM_ANON 2

struct vm_entry
{
  uint8_t type;			/* Type of VM_ENTRY. */
  void *vaddr;			/* Virtual address number. */
  bool writable;		/* If true, can write that address. */

  bool is_loaded;		/* Physical page is loaded. */
  struct file* file;		/* Mapped file name. */
  bool pinned;			/* The page pinned can't evict victim. */

  struct list_elem mmap_elem;	/* Element of VME_LIST. */

  size_t offset;		/* File offset to read. */
  size_t read_bytes;		/* Valid datasize in virtual address. */
  size_t zero_bytes;		/* In valid datasize in virtual address. */

  size_t swap_slot;		/* Save the index swap bitmap. */

  struct hash_elem elem;	/* Element of hash table. */
};

struct mmap_file
{
  int mapid;			/* File's MAPID. */
  struct file* file;		/* Mapping file object. */
  struct list_elem elem;	/* Element of MMAP_LIST. */
  struct list vme_list;		/* List of vm_entry which correspond to FILE. */
};

struct page
{
  void *kaddr;			/* Address of physical memory. */
  struct vm_entry *vme;		/* Mapped vm_entry. */
  struct thread *thread;	/* Thread using this page. */
  struct list_elem lru;		/* Element of LRU_LIST. */
};

typedef int mapid_t;

void vm_init (struct hash *vm);
static unsigned vm_hash_func (const struct hash_elem *e, void *aux);
static bool vm_less_func (const struct hash_elem *a, const struct hash_elem *b);
bool insert_vme (struct hash *vm, struct vm_entry *vme);
bool delete_vme (struct hash *vm, struct vm_entry *vme);
struct vm_entry *find_vme (void *vaddr);
void vm_destroy (struct hash *vm);
void vm_hash_action_func (struct hash_elem *e, void *aux);

#endif
