#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
struct thread *get_child_process (int pid);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* Parse file name and Give it to thread_create (). */
  int name_size;
  name_size = strlen (file_name) + 1;

  char file_name_copy[name_size];
  strlcpy (file_name_copy, file_name, name_size);

  char *save_ptr;
  char *thread_name;
  thread_name = strtok_r (file_name_copy, " ", &save_ptr);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (thread_name, PRI_DEFAULT, start_process, fn_copy);
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy);
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  char *fn_copy;
  char *token;
  char *save_ptr;
  char **parse;
  int count;
  int i;

  /* Allocate page for fn_copy. strtok_r() modify page information, so we use copy of it.
     If fails, free page and exit thread. */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
  {
    palloc_free_page (file_name);
    thread_exit ();
  }
  strlcpy (fn_copy, file_name, PGSIZE);

  count = 0;
  /* Allocate page for storing parsed fn_copy.
     If fails, free page and exit thread. */
  parse = palloc_get_page(0);
  if (parse == NULL)
  {
    palloc_free_page (file_name);
    palloc_free_page (fn_copy);
    thread_exit ();
  }

  /* Tokenize fn_copy. If page allocation error occur,
     free all allocated page, and exit thread. */
  for (token = strtok_r (fn_copy, " ", &save_ptr) ; token != NULL ;
        token = strtok_r (NULL, " ", &save_ptr))
  {
    parse[count] = palloc_get_page (0);

    /* Check if page allocation error occur. */
    if (parse[count] == NULL)
    {
      int j;
      for (j = 0; j < count; j++)
        palloc_free_page (parse[j]);
      palloc_free_page (parse);
      palloc_free_page (fn_copy);
      palloc_free_page (file_name);
      thread_exit ();
    }
    /* Save tokenized fn_copy into parse. */
    strlcpy (parse[count], token, PGSIZE);
    count++;
  }
  /* Init hash table using vm_init(). */
  vm_init (&thread_current ()->vm);

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (parse[0], &if_.eip, &if_.esp);

  /* If load end, continue parent process.
     Change load flag here, because immediate sema_up after load can cause ordering error. */
  thread_current()->is_load = success;
  sema_up(&thread_current()->load);

  /* If load success, put tokenized file into stack pointer. */
  if (success)
    argument_stack (parse, count, &if_.esp);

  /* If load failed, quit. */
  palloc_free_page (file_name);
  if (!success)
  {
    for(i = 0 ; i < count ; i++)
      palloc_free_page (parse[i]);
    palloc_free_page (parse);
    palloc_free_page (fn_copy);
    thread_exit ();
  }

  /* Always do free allocated page at the end of function . */
  for (i = 0 ; i < count ; i++)
    palloc_free_page (parse[i]);
  palloc_free_page (parse);
  palloc_free_page (fn_copy);

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED) 
{
  struct thread *cp;
  int status;

  /* Get child process using child's tid. */
  cp = get_child_process (child_tid);

  /* If fail, return abnormal result(-1) . */
  if (cp == NULL)
    return -1;

  /* Waits until child process end. */
  sema_down (&cp->exit);

  /* Check if child process end normally. */
  status = cp->exit_status;

  /* Remove finished child process. */
  remove_child_process (cp);
  return status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Close all file in process by using next file descriptor position.
     And free file descriptor table. */
  int i;
  for (i = 2; i < cur->next_fd; i++){
      process_close_file (i);
  }
  palloc_free_page (cur->fdt);

  /* Close all mapped file. */
  munmap (CLOSE_ALL);

  /* Destroy hash table and vm_entrys. */
  vm_destroy (&cur->vm);

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Acquire Lock to avoid multiple access. */
  lock_acquire (&filesys_lock);

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL) 
  {
    /* release lock before end. */
    lock_release (&filesys_lock);
    printf ("load: %s: open failed\n", file_name);
    goto done; 
  }
  /* Deny write to avoid file change. */
  file_deny_write (file);

  /* After file open done, release lock. */
  lock_release (&filesys_lock);

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Allocate vm_entry VME and fill it's members.
         Then insert it to hash table. */
      struct vm_entry *vme;
      vme = malloc (sizeof(struct vm_entry));
      if (vme == NULL)
        return false;
      /* If we use given file pointer FILE, It occur
         pointer don't keep file information.
         So use file_reopen() to keep information. */
      vme->file = file_reopen(file);
      vme->vaddr = upage;
      vme->offset = ofs;
      vme->read_bytes = page_read_bytes;
      vme->zero_bytes = page_zero_bytes;
      vme->writable = writable;
      vme->is_loaded = false;
      vme->type = VM_BIN;
      vme->pinned = false;
      insert_vme (&thread_current ()->vm, vme);

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      ofs += page_read_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  struct page *kpage;
  bool success = false;
  /* Allocate page using alloc_page(). */
  kpage = alloc_page (PAL_USER | PAL_ZERO);
  if (kpage->kaddr != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage->kaddr, true);
      if (success)
        *esp = PHYS_BASE;
      else
        free_page (kpage->kaddr);
    }
  /* Allocate vm_entry VME and fill it's members.
     Then insert it to hash table. */
  struct vm_entry *vme;
  vme = malloc (sizeof(struct vm_entry));
  if (vme == NULL)
    {
      free_page (kpage->kaddr);
      return false;
    }
  vme->writable = true;
  vme->vaddr = pg_round_down(((uint8_t *) PHYS_BASE) - PGSIZE);
  vme->is_loaded = true;
  vme->type = VM_ANON;
  vme->pinned = true;
  kpage->vme = vme;
  success = insert_vme (&thread_current ()->vm, vme);
  return true;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

/* Save user stack into kernel stack. */
void
argument_stack(char **parse, int count, void **esp)
{
  int i, j;
  char *argv;
  char *argv_each[count];
  int word_count;

  /* word_count check how many word in file name. */
  word_count = 0;

  /* Push file name in stack. */
  for (i = count - 1 ; i > -1 ; i--)
  {
    for (j = strlen(parse[i]) ; j > -1 ; j--)
    {
      *esp = *esp - 1;
      **(char **)esp = parse[i][j];
      word_count++;
    }
    /* Save each start point of argv into array. */
    argv_each[i] = *esp;
  }

  /* Align pointer to be multiple of 4 */
  for (i = 0 ; i < (4 - word_count % 4) % 4 ; i++)
  {
    *esp = *esp - 1;
    **(uint8_t **)esp = 0;
  }
  
  /* Last argv is always null. */
  *esp = *esp - 4;
  **(char ***)esp = 0;

  /* Put argv[0] to argv[count - 1] */
  for (i = count - 1 ; i > -1 ; i--)
  {
    *esp = *esp - 4;
    **(char ***)esp = argv_each[i];
  }

  /* Save current stack top pointer which is argv. */
  argv = *esp;
  *esp = *esp - 4;
  **(char ***)esp = argv;

  /* argc is equal to count. */
  *esp = *esp - 4;
  **(int **)esp = count;

  /* Put fake address. */
  *esp = *esp - 4;
  **(char ***)esp = 0;
}

/* Get child process by using pid.
   Compare pid with all process in child process list. */
struct thread *
get_child_process (int pid)
{
  struct list_elem *e;
  struct list *child_list;
  struct thread *cp;

  /* Get current process's child process list and compare with pid. */
  child_list = &thread_current ()->child_process;
  for (e = list_begin (child_list); e != list_end (child_list); e = list_next (e))
  {
    cp = list_entry (e, struct thread, childelem);
    if (cp->tid == pid)
      return cp;
  }
  /* If no correspond child process, return NULL. */
  return NULL;
}

/* Remove given child process. */
void
remove_child_process (struct thread *cp)
{
  /* If given child process is invalid, return. */
  if (cp == NULL)
    return;

  /* remove child process from parent process's child list, and free. */
  list_remove (&cp->childelem);
  palloc_free_page (cp);
}

/* Put file into file descriptor table and change next position of addition. */
int
process_add_file (struct file *f)
{
  /* Next position for addition. */ 
  int next_fd;

  /* Put file into file descriptor table. */
  next_fd = thread_current ()->next_fd;
  thread_current ()->fdt[next_fd] = f;

  /* Point next empty space in file descriptor table. */
  thread_current ()->next_fd += 1;

  /* Return where file is. */
  return next_fd;
}

/* Get file from file descriptor table.
   If there is no file in corresponding position, return NULL */
struct file *
process_get_file (int fd)
{
  /* If fd is invalid, return NULL. */
  if (fd >= thread_current ()->next_fd)
    return NULL;
  /* If fd is valid, return file in file descriptor table. */
  return thread_current ()->fdt[fd];
}

/* Close corresponding file in file descriptor table.
   After that, initialize corresponding entry. */
void
process_close_file (int fd)
{
  struct file *del_file;

  /* Get file from file descriptor table using fd. */
  del_file = process_get_file (fd);

  /* If there is no file, return. */
  if (del_file == NULL)
    return;

  /* Close file and initialize corresponding entry. */
  file_close(del_file);
  thread_current ()->fdt[fd] = NULL;
}

bool
handle_mm_fault (struct vm_entry *vme)
{
  struct page *kpage;
  bool load;

  /* Allocate page using alloc_page. */
  kpage = alloc_page (PAL_USER);

  /* If physical page is already loaded return false. */
  if (vme->is_loaded)
    {
      free_page(kpage->kaddr);
      return false;
    }
  if (kpage->kaddr == NULL)
    return false;
  
  /* If type of VME is VM_BIN or VM_FILE load physical
     page using load_file(). Or VM_ANON do swapping to
     get page information from swap block location. */
  switch (vme->type)
    {
      case VM_BIN:
        load = load_file (kpage->kaddr, vme);
        if (load == false)
          {
            free_page (kpage->kaddr);
            return false;
          }
        break;
      case VM_FILE:
        load = load_file (kpage->kaddr, vme);
        if (load == false)
          {
            free_page (kpage->kaddr);
            return false;
          }
        break;
      case VM_ANON:
        swap_in (vme->swap_slot, kpage->kaddr);
        break;
      default:
        return false;
    }
  /* Mapping physical page and virtual page. */
  load = install_page (vme->vaddr, kpage->kaddr, vme->writable);
  if (load == false)
    {
      free_page (kpage->kaddr);
      return false;
    }
  /* Set IS_LOADED to true because physical page is
     successfully loaded. */
  vme->is_loaded = true;
  
  /* Set physical page's virtual page to VME. */
  kpage->vme = vme;
  return true;
}

bool
expand_stack(void *addr)
{
  struct vm_entry *vme;
  struct page *page;
  /* If stack size over 8MB fail. */
  if(addr < PHYS_BASE - 8 * 1048576)
    return false;

  /* Make vm_entry and insert to hash table. */
  vme = (struct vm_entry *)malloc(sizeof(struct vm_entry));
  vme->vaddr = pg_round_down(addr);
  vme->writable = true;
  vme->is_loaded = true;
  vme->type = VM_ANON;
  vme->pinned = true;
  /* Allocate page and mapping physical page.  */
  page = alloc_page(PAL_USER);
  if(page == NULL)
    {
      free(vme);
      return false;
    }
  page->vme=vme;
  if(install_page(vme->vaddr,page->kaddr,vme->writable) == false)
    {
      free_page(page);
      free(vme);
      return false;
    }
  if(!insert_vme (&thread_current ()->vm, vme))
    {
      free_page(page);
      free(vme);
      return false;
    }
  return true;
}
