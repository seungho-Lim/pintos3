#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "devices/input.h"
#include "filesys/file.h"
#include "vm/page.h"


static void syscall_handler (struct intr_frame *);

struct vm_entry *check_address (void *addr, void *esp);
void get_argument (void *esp, int *arg, int count);
void halt (void);
void exit (int status);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
tid_t exec (const char *cmd_line);
int wait (tid_t tid);
int open (const char *file);
int filesize(int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

void unpin(void *addr);
void unpin_string(void *str);
void unpin_buffer(void *buffer, unsigned size);

void
syscall_init (void) 
{
  /* filesys_lock control accessibility for file system. */
  lock_init (&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* System Call handler takes data from stack,
   and do corresponing job. */

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  /* System Call Can have at most 3 values. */
  int arg[3];
  /* which job to do? */
  int syscall_number;

  /* Check stack pointer point vaild address. */
  check_address ((void *)(f->esp), (void *)(f->esp));

  /* Takes Syscall Number from esp. */
  syscall_number = *(int *)(f->esp);
  switch(syscall_number)
  {
    /* Halt Operation turn off system. */
    case SYS_HALT:
      halt();
      break;
    /* Exit Current Process. */
    case SYS_EXIT:
      get_argument(f->esp, arg, 1);
      exit(arg[0]);
      break;
    /* Make Child Process. */
    case SYS_EXEC:
      get_argument(f->esp, arg, 1);
      check_valid_string((void *)arg[0], f->esp);
      f->eax = exec((const char *)arg[0]);
      break;
    /* Wait until child process end. */
    case SYS_WAIT:
      get_argument(f->esp, arg, 1);
      f->eax = wait((tid_t)arg[0]);
      break;
    /* Create file. */
    case SYS_CREATE:
      get_argument(f->esp, arg, 2);
      check_valid_string((void *)arg[0], f->esp);
      f->eax = create((const char *)arg[0], (int)arg[1]);
      break;
    /* Remove file. */
    case SYS_REMOVE:
      get_argument(f->esp, arg, 1);
      check_valid_string((void *)arg[0], f->esp);
      f->eax = remove((const char *)arg[0]);
      break;
    /* Open File. */
    case SYS_OPEN:
      get_argument(f->esp, arg, 1);
      check_valid_string((void *)arg[0], f->esp);
      f->eax = open((const char *)arg[0]);
      break;
    /* Return Filesize. */
    case SYS_FILESIZE:
      get_argument(f->esp, arg, 1);
      f->eax = filesize((int)arg[0]);
      break;
    /* Read File from command line or file. */
    case SYS_READ:
      get_argument(f->esp, arg, 3);
      check_valid_buffer((void *)arg[1], (unsigned)arg[2], f->esp, true);
      pin_buffer ((void *)arg[1],(unsigned)arg[2],f->esp);
      f->eax = read((int)arg[0], (void *)arg[1], (unsigned)arg[2]);
      break;
    /* Write File at monitor or file. */
    case SYS_WRITE:
      get_argument(f->esp, arg, 3);
      check_valid_buffer((void *)arg[1], (unsigned)arg[2], f->esp, false);
      //pin_buffer ((void *)arg[1],(unsigned)arg[2],f->esp);
      f->eax = write((int)arg[0], (void *)arg[1], (unsigned)arg[2]);
      break;
    /* Change offset. */
    case SYS_SEEK:
      get_argument(f->esp, arg, 2);
      seek((int)arg[0], (unsigned)arg[1]);
      break;
    /* Take Offset. */
    case SYS_TELL:
      get_argument(f->esp, arg, 1);
      f->eax = tell((int)arg[0]);
      break;
    /* Close File. */
    case SYS_CLOSE:
      get_argument(f->esp, arg, 1);
      close((int)arg[0]);
      break;
    case SYS_MMAP:
      get_argument(f->esp, arg, 2);
      f->eax = mmap(arg[0], (void *)arg[1]);
      break; 
    case SYS_MUNMAP:
      get_argument(f->esp, arg, 1);
      munmap(arg[0]);
      break; 
    /* Else, exit thread. */
    default:
      thread_exit();
      break;
  }
  unpin (f->esp);
}

/* Check pointer points User Area. */
struct vm_entry *
check_address (void *addr, void *esp UNUSED)
{
  /* If pointer points Kernel Area of invalid area, exit process. */
  if ((unsigned)addr < 0x8048000 || (unsigned)addr >= 0xc0000000)
    exit (-1);
  
  return find_vme (addr);
}

/* Get argument from stack for 4 byte. */
void
get_argument (void *esp, int *arg, int count)
{
  int i;
  for(i = 0; i < count; i++)
  {
    /* Always check if pointer points valid area. */
    check_address (esp + 4 + 4 * i, esp + 4 + 4 * i);
    arg[i] = *(int *)(esp + 4 + 4 * i);
  }
}

/* Halt Shutdown machine. */
void
halt (void)
{
  shutdown_power_off();
}

/* Exit current process. */
void
exit (int status)
{
  struct thread *cur = thread_current ();

  /* Assign how current process ends. And exit thread. */
  cur->exit_status = status;
  printf ("%s: exit(%d)\n", cur->name, status);
  thread_exit ();
}

/* Create file using filesys_create (). */
bool
create (const char *file, unsigned initial_size)
{
  unpin_string (file);

  /* If file is invalid, return false. */
  if (file == NULL)
    return false;
  return filesys_create(file, initial_size);

}

/* Remove file using filesys_remove (). */
bool
remove (const char *file)
{
  /* If file is invalid, return false. */
  if (file == NULL)
    return false;
  return filesys_remove(file);
}

/* Create child process and execute it.
   If creation success, return pid. If fail, return -1.
   Parent process waits until end of child process loading. */
tid_t
exec (const char *cmd_line)
{
  int tid;
  struct thread *cp;

  /* Create child process which name is what cmdline point to. */
  tid = process_execute (cmd_line);
  cp = get_child_process (tid);

  /* Wait until end of loading child process. */
  sema_down (&cp->load);

  unpin_string(cmd_line);
  /* If creation fail, return -1. */
  if (cp == NULL)
    return -1;

  /* If load fail, return -1. */
  if (cp->is_load == false)
    return -1;

  /* If success, return tid. */
    return tid;
}

/* Wait until child process end by using process_wait() function. */
int
wait (tid_t tid)
{
  return process_wait (tid);
}

/* Open file. If success, return file descriptor, else, return -1. */
int
open (const char *file)
{
  /* If file name pointer is invalid, return -1. */
  if (file == NULL)
  {
    unpin_string(file);
    return -1;
  }  
  struct file *f;

  /* Acquire Lock to avoid multiple access to file. */
  lock_acquire (&filesys_lock);

  /* Open file */
  f = filesys_open (file);

  /* If file is invalid, release lock and return -1. */
  if (f == NULL)
  {
    lock_release (&filesys_lock);
    unpin_string(file);
    return -1;
  }

  /* If file is as same as currently opened file, avoid multiple write. */
  if (strcmp (file,thread_current ()->name) == 0)
    file_deny_write(f);

  /* If file descriptor table is full, return -1.
     If all condition is clear, return file descriptor. */
  int results;
  results = process_add_file (f);

  /* After all job finished, release lock. */
  lock_release(&filesys_lock);
  unpin_string(file);
  if (results == 64)
    return -1;
  return results;
}

/* Give size of file in file descriptor table.
   If success, return its size, else, return -1. */
int
filesize (int fd)
{
  struct file *f;

  /* Search file using file descriptor. */
  f = process_get_file (fd);

  /* If file is invalid, return -1. */
  if (f == NULL)
    return -1;

  /* If file is valid, return file size. */
  return file_length (f);
}

/* Read file for certain size. Save it to buffer. */
int
read (int fd, void *buffer, unsigned size)
{
  struct file *f;
  int i;

  /* Acquire lock to avoid multiple file access. */
  lock_acquire (&filesys_lock);

  /* get file from file descriptor table. */
  f = process_get_file (fd);
  /* If file read from standard input, */
  if(fd == 0)
  {
    for (i = 0; i < size; i++)
    {
      /* using input_getc () function to read from keyboard input.*/
      *(uint8_t *)(buffer + i) = input_getc ();
    }
    /* After reading, release lock and return size. */
    lock_release (&filesys_lock);
    unpin_buffer(buffer, size);
    return size;
  }
  /* If file read from certain file in file descriptor table, */
  else
  {
    int sizes;
    /* If file is invalid, return -1. */
    if (f == NULL)
    {
      /* Don't forget relase lock before end. */
      lock_release (&filesys_lock);
      unpin_buffer(buffer, size);
      return -1;
    }
    /* read file by using file_read function. */
    sizes = file_read (f, buffer, size);
    /* After reading, release lock and return size. */
    lock_release (&filesys_lock);
    unpin_buffer(buffer, size);
    return sizes;
  }
}

/* Write file for certain size. Contend is in buffer. */
int
write (int fd, void *buffer, unsigned size)
{
  struct file *f;
  /* Check file descriptor is invalid. */
  if(fd <= 0)
    {
      unpin_buffer(buffer, size);
      return -1;
    }
  /* Acquire lock to avoid multiple access. */
  lock_acquire (&filesys_lock);

  /* Get file from file descriptor table. */
  f = process_get_file (fd);

  /* If write file for standard output, */
  if(fd == 1)
  {
    /* Using putbuf () function. */
    putbuf (buffer, size);
    /* After writing, release lock. And return size. */
    lock_release (&filesys_lock);
    unpin_buffer(buffer, size);
    return size;
  }
  /* If write file which is in file descriptor table, */
  else
  {
    int sizes;
    /* If file is invalid, return -1. */
    if (f == NULL)
    {
      /* Don't forget release lock before end. */
      lock_release (&filesys_lock);
      unpin_buffer(buffer, size);
      return -1;
    }

    /* write file by using file_write () function. */
    sizes = file_write (f, buffer, size);
    /* After writing, release lock and return size. */
    lock_release (&filesys_lock);
    unpin_buffer(buffer, size);
    return sizes;
  }
}

/* Change opened file's offset (Position). */
void
seek (int fd, unsigned position)
{
  struct file *f;

  /* Get file from file descriptor table. */
  f = process_get_file (fd);

  /* Seek file by using file_seek () function. */
  file_seek(f, position);
}

/* Search file using file descriptor and return offset. */
unsigned
tell (int fd)
{
  struct file *f;

  /* Get file from file descriptor table. */
  f = process_get_file (fd);

  /* Return offset by using file_tell () function. */
  return file_tell (f);
}

/* Close file by using process_close_file function. */
void
close (int fd)
{
  process_close_file (fd);
}

void
check_valid_buffer (void *buffer, unsigned size, void *esp, bool to_write)
{
  int i;
  struct vm_entry *vme;
  /* Check buffer's address is valid or not.
     It's range is BUFFER to BUFFER+SIZE. */
  for (i = 0; i < size; i++)
    {
      vme = check_address ((char *)buffer + i, esp);
      if (vme && to_write)
        {
          if (vme->writable == false)
            exit (-1);
        }
    }
}

void
check_valid_string (const void *str, void *esp)
{
  /* Check string's address is valid or not.
     It's range is STR to NULL. */
  char *strs = (char *)str;
  while (*strs)
  {
    if (check_address ((void*)strs, esp) == NULL)
      exit (-1);
    strs++;
  }
}  

int
mmap (int fd, void *addr)
{
  struct file *file;
  file = process_get_file (fd);
  /* ADDR need to be align 4KB and can't be NULL */
  if (file == NULL || addr == NULL || (uint32_t)addr % PGSIZE != 0)
    return -1;
  /* If there isn't vm_entry correspond to ADDR, fail. */
  if (find_vme (addr) != NULL)
    return -1;

  /* Allocate file and set members. */
  struct mmap_file *mmap;
  mmap = malloc (sizeof (struct mmap_file));
  if (mmap == NULL)
    return -1;

  mmap->file = file_reopen (file);
  if (mmap->file == NULL)
    {
      free (mmap);
      return -1;
    }
  /* In same thread, there isn't any same MAPID. */
  mmap->mapid = thread_current ()->mapid++;

  list_init (&mmap->vme_list);

  /* Make VME and set file information(READ_BYTES...).
     And insert VME to VME_LIST, hash table. Also insert
     MMAP to MMAP_LIST.*/
  struct vm_entry *vme;
  size_t length;
  size_t page_read_bytes;
  size_t page_zero_bytes;
  int offset;
  length = file_length (mmap->file);
  offset = 0;
  while (length > 0)
    {
      if (find_vme (addr) != NULL)
        return -1;

      page_read_bytes = length < PGSIZE ? length : PGSIZE;
      page_zero_bytes = PGSIZE - page_read_bytes;
  
      vme = malloc (sizeof (struct vm_entry));
      if (vme == NULL)
        return -1;
      vme->file = mmap->file;
      vme->vaddr = addr;
      vme->offset = offset;
      vme->read_bytes = page_read_bytes;
      vme->zero_bytes = page_zero_bytes;
      vme->writable = true;
      vme->is_loaded = false;
      vme->type = VM_FILE;
      vme->pinned = false;
  
      insert_vme (&thread_current ()->vm, vme);  
  
      length -= page_read_bytes;
      offset += page_read_bytes;
      addr += PGSIZE;

      list_push_back (&mmap->vme_list, &vme->mmap_elem);
    }
  list_push_back (&thread_current ()->mmap_list, &mmap->elem);

  return mmap->mapid;
}

void
munmap (int mapping)
{
  /* Unmap vm_entrys which MAPID is MAPPING. Or MAPPING is CLOSE_ALL,
     unmap all file. Call do_munmap() to remover maping. */
  struct mmap_file *mmap_file;
  struct list_elem *e;
  struct thread *cur;
  cur = thread_current ();
  for (e = list_begin (&cur->mmap_list);
		e != list_end (&cur->mmap_list); e = list_next(e))
    {
      mmap_file = list_entry (e, struct mmap_file, elem);
      if (mapping == CLOSE_ALL || mapping == mmap_file->mapid)
        {
          do_munmap (mmap_file);
          file_close (mmap_file->file);
          e = list_prev(list_remove (e));
          free (mmap_file);
        }
    }
}

void
do_munmap (struct mmap_file *mmap_file)
{
  struct vm_entry *vme;
  struct list_elem *e;
  struct list *vme_list;
  struct thread *cur;
  int size;
  cur = thread_current ();
  vme_list = &mmap_file->vme_list;
  void *kaddr;
  /* Delete all vm_entry which linked MMAP_FILE. If VME_VADDR's
     dirty bit is 1, write memory information to disk. */
  for (e = list_begin (vme_list); e != list_end (vme_list); e = list_next(e))
    {
      vme = list_entry (e, struct vm_entry, mmap_elem);
      if (vme->is_loaded)
        {
          kaddr = pagedir_get_page (cur->pagedir, vme->vaddr);
          if(pagedir_is_dirty (cur->pagedir, vme->vaddr))
            {
              lock_acquire (&filesys_lock);
              file_write_at (vme->file, vme->vaddr, vme->read_bytes, vme->offset);
              lock_release (&filesys_lock);
            }
          pagedir_clear_page(cur->pagedir, vme->vaddr);
          free_page (kaddr);
        }
      e = list_prev(list_remove (e));
      delete_vme (&cur->vm, vme);
    }
}

void
unpin(void *addr)
{
  /* Set page to unpinning page after syscall. */
  struct vm_entry *vme = find_vme(addr);
  if(vme != NULL)
    {
      vme->pinned =false;
    }
}

void
unpin_string(void *str)
{
  /* For all str to NULL set unpinning page. */
  unpin(str);
  while(*(char *)str !=0)
    {
      str = (char *)str+1;
      unpin(str);
    }
}

void
unpin_buffer(void *buffer, unsigned size)
{
  /* For all BUFFERS to BUFFERS+SIZE set unpinning page. */
  unsigned i;
  char *buffers = (char *)buffer;
  for(i=0;i<size;i++)
    {
      unpin(buffers);
      buffers++;
    }
}

void
pin (void *addr,void *esp)
{
  /* Set page to pinning page when do syscall. */
  struct vm_entry *vme = find_vme (addr);
  if(vme == NULL)
    {
      if(addr >= esp - 32)
        {
          expand_stack(addr);
          vme = find_vme (addr);
        }
    }
  if (vme->writable == false)
    exit (-1);
  vme->pinned = true;
  if (vme->is_loaded == false)
    handle_mm_fault (vme);
}

void
pin_buffer(void *buffer, unsigned size,void *esp)
{
  /* For all BUFFERS to BUFFERS+SIZE set pinning page. */
  unsigned i;
  char *buffers = (char *)buffer;
  for(i=0;i<size;i++)
    {
      pin(buffers,esp);
      buffers++;
    }
}
