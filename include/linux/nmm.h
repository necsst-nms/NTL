#ifndef NMM_H
#define NMM_H

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/mm_types.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/radix-tree.h>
#include <linux/btree.h>

#define bool int
#define true 1
#define false 0

// SizeQuant: 4 --> 1
#define SizeQuant   1		     

#define assert(cond) 											\
do 																\
{																\
	if (!(cond)) 												\
	{															\
		printk("Failed assertion in %s: %s at %s, line %d\n", 	\
			__func__, #cond, __FILE__, __LINE__);   			\
	} 															\
} 																\
while (0); 															

typedef long bufsize;

typedef unsigned long ulong_t;
typedef unsigned int uint_t;
typedef unsigned short ushort_t;
typedef unsigned char uchar_t;

// MemSize: int --> char
#define MemSize     char	      

/* Queue links */
struct qlinks {
    struct bfhead *flink;	      /* Forward link */
    struct bfhead *blink;	      /* Backward link */
};

/* Header in allocated and free buffers */
struct bhead {
    bufsize prevfree;			/* Relative link back to previous
					 free buffer in memory or 0 if
					 previous buffer is allocated.	*/
    bufsize bsize;				/* Buffer size: positive if free,
					 negative if allocated. */
};
#define BH(p)	((struct bhead *) (p))

/* Header in free buffers */
struct bfhead {
    struct bhead bh;		      /* Common allocated/free header */
    struct qlinks ql;		      /* Links on free list */
};
#define BFH(p)	((struct bfhead *) (p))

/*  Minimum allocation quantum: */
#define QLSize	(sizeof(struct qlinks))
#define SizeQ	((SizeQuant > QLSize) ? SizeQuant : QLSize)

#define V   (void)		      /* To denote unwanted returned values */

/* End sentinel: value placed in bsize field of dummy block delimiting
   end of pool block.  The most negative number which will  fit  in  a
   bufsize, defined in a way that the compiler will accept. */

#define ESent	((bufsize) (-(((1L << (sizeof(bufsize) * 8 - 2)) - 1) * 2) - 2))


/* For NVFAT write cache */
struct nmm_mng_wcache
{
	// spin_lock variable

	/* for the NVFAT file system */
	struct list_head lru_list;

	int nr_caches;
};

/* For NM management */
#define WCACHE_HASH_SIZE 64

struct wcache_lock_hash
{
	spinlock_t hashtable_lock;
	struct hlist_head hashtable[WCACHE_HASH_SIZE];
};	

struct mm_nm
{
	unsigned int nm_start_vaddr;

	struct nmm_mng_wcache nm_mng_header;

	struct wcache_lock_hash wcache_hashtable;

	/* for NM management */
	struct bfhead s_freelist;
};

//////////////////////////////////////////////////////
// Authored by Hyunsub Song
// NTL

/* For linked list */
/* struct nm_pfn_struct {
	unsigned long pfn;
	void *data_vaddr;
	size_t bytes;
	struct list_head list;
};

static LIST_HEAD(nm_pfn_list); */

/* For red-black tree */
/* struct nm_pfn_struct {
	unsigned long pfn;
	void *data_vaddr;
	size_t bytes;
	struct rb_node node;
};

static struct rb_root rb_root_tree = RB_ROOT;*/

/* For radix-tree */
struct nm_pfn_struct {
	unsigned long pfn;
	void *data_vaddr;
	size_t bytes;
};

/* For b+ tree */
// static struct btree_head b_root;


// static struct radix_tree_root rd_root;

/* test for check number of write request */
/* struct nm_pfn_struct_array {
	struct nm_pfn_struct nm_pfn[300000];
};

static struct nm_pfn_struct_array *metadata_start_addr;
static int data_access_num = 0; */
///////////////////////////////////////////////////////

// 32Bit 4GB Memory
//#define NM_ADDR 0x60000000		/* 0xA0000000 (DRAM base) + 32MB location */
//#define NM_SIZE 32*1024*1024	/* 32 MB */
// 64Bit 4GB Memory
// #define NM_ADDR 0x90000000
// #define NM_SIZE 512*1024*1024
// 64Bit 32GB Memory
// #define NM_ADDR 0x790000000
// #define NM_SIZE 1024*1024*1024
// 64Bit 64GM Memory
#define NM_ADDR 0x800000000
// #define NM_SIZE 10*1024*1024*1024
#define NM_SIZE 1024*1024*1024

//#define NM_ADDR 0xA3000000
//#define NM_SIZE 8*1024*1024

// struct bfhead *nmm_flist;     /* List of free buffers */

void bpool(void *buffer, bufsize len);
void *bget(bufsize size);
void *bgetz(bufsize size);
void brel(void *buf);

extern void *nm_alloc(ulong_t size);
extern void nm_free(void *buf);

////////////////////////////////////////////////////////
// Authored by Hyunsub Song
// NTL
extern size_t nm_write(unsigned long pfn, struct page *page, struct iov_iter *i, unsigned long offset, size_t bytes, struct radix_tree_root *rd_root, spinlock_t *tree_lock);
extern size_t nm_write_3(unsigned long pfn, struct bio *bio, struct radix_tree_root *rd_root, spinlock_t *tree_lock);
extern int nm_read(unsigned long pfn, read_descriptor_t *desc, struct page *page, unsigned long offset, unsigned long size, struct radix_tree_root *rd_root);
// extern int nm_read_3(unsigned long pfn, read_descriptor_t

/* For red-black tree */
// struct nm_pfn_struct* nm_rb_create(unsigned long pfn, size_t bytes);
// struct nm_pfn_struct* __nm_rb_insert(struct rb_root *root, struct nm_pfn_struct *new_node);
// struct nm_pfn_struct* nm_rb_insert(struct rb_root *root, struct nm_pfn_struct *new_node);
// struct nm_pfn_struct* nm_rb_search(struct rb_root *root, unsigned long pfn);
// void __nm_rb_print(struct rb_node *tmp_node, int depth, int destination);
// void nm_rb_print(struct rb_root *root);

/* For radix-tree */
struct nm_pfn_struct* nm_rd_create(unsigned long pfn, size_t bytes);
void nm_rd_insert(struct nm_pfn_struct *new_node, struct radix_tree_root *rd_root, spinlock_t *tree_lock);
struct nm_pfn_struct* nm_rd_search(unsigned long pfn, struct radix_tree_root *rd_root);
////////////////////////////////////////////////////////

extern struct list_head *get_nmm_lru_head(void);
extern struct hlist_head *get_nmm_wcache_hashtable(void);
extern int *get_nmm_nr_caches(void);
// extern void nmm_test();

#endif
