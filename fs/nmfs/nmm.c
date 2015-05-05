// Original version of BGET downloaded from: http://www.fourmilab.ch/bget/

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/list.h>
#include <asm/io.h>
#include <linux/nmm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/rbtree.h>
#include <linux/radix-tree.h>
#include <linux/ktime.h>
#include <linux/pagemap.h>
#include <linux/uio.h>
#include <linux/rcupdate.h>
#include <linux/btree.h>

// #include "../../arch/ia64/include/asm/io.h"
// #include <linux/io.h>


#define CONFIG_INIT_NMM
#define CONFIG_DEBUG_NMM

ktime_t ktime_get(void);

struct mm_nm *manage_nm;


struct bfhead *nmm_flist;     /* List of free buffers */

unsigned int usage_nm = 0;
unsigned int max_usage_nm = 0;

// unsigned char *nm_vaddr;

/*  BGET  --  Allocate a buffer.  */

void *bget(bufsize requested_size)
{
    bufsize size = requested_size;
    struct bfhead *b;
    void *buf;

    assert(size > 0);

    if (size < SizeQ) { 	      /* Need at least room for the */
		size = SizeQ;		      /*    queue links.  */
    }
#ifdef SizeQuant
#if SizeQuant > 1
    size = (size + (SizeQuant - 1)) & (~(SizeQuant - 1));
#endif
#endif

    size += sizeof(struct bhead);     /* Add overhead in allocated buffer
										 to size required. */

	b = nmm_flist->ql.flink;
#ifdef BestFit
	best = nmm_flist;
#endif


	/* Scan the free list searching for the first buffer big enough
	   to hold the requested size buffer. */

#ifdef BestFit
	while (b != nmm_flist) {
	    if (b->bh.bsize >= size) {
			if ((best == nmm_flist) || (b->bh.bsize < best->bh.bsize)) {
				best = b;
			}
	    }
	    b = b->ql.flink;		  /* Link to next buffer */
	}
	b = best;
#endif /* BestFit */

	while (b != nmm_flist) {
	    if ((bufsize) b->bh.bsize >= size) {

		/* Buffer  is big enough to satisfy  the request.  Allocate it
		   to the caller.  We must decide whether the buffer is  large
		   enough  to  split  into  the part given to the caller and a
		   free buffer that remains on the free list, or  whether  the
		   entire  buffer  should  be  removed	from the free list and
		   given to the caller in its entirety.   We  only  split  the
		   buffer if enough room remains for a header plus the minimum
		   quantum of allocation. */

			if ((b->bh.bsize - size) > (SizeQ + (sizeof(struct bhead)))) {
				struct bhead *ba, *bn;

				ba = BH(((char *) b) + (b->bh.bsize - size));
				bn = BH(((char *) ba) + size);
				assert(bn->prevfree == b->bh.bsize);
				/* Subtract size from length of free block. */
				b->bh.bsize -= size;
				/* Link allocated buffer to the previous free buffer. */
				ba->prevfree = b->bh.bsize;
				/* Plug negative size into user buffer. */
				ba->bsize = -(bufsize) size;
				/* Mark buffer after this one not preceded by free block. */
				bn->prevfree = 0;

				buf = (void *) ((((char *) ba) + sizeof(struct bhead)));
				return buf;
			} else {
				struct bhead *ba;

				ba = BH(((char *) b) + b->bh.bsize);
				assert(ba->prevfree == b->bh.bsize);

				/* The buffer isn't big enough to split.  Give  the  whole
				   shebang to the caller and remove it from the free list. */

				assert(b->ql.blink->ql.flink == b);
				assert(b->ql.flink->ql.blink == b);
				b->ql.blink->ql.flink = b->ql.flink;
				b->ql.flink->ql.blink = b->ql.blink;

				/* Negate size to mark buffer allocated. */
				b->bh.bsize = -(b->bh.bsize);

				/* Zero the back pointer in the next buffer in memory
				   to indicate that this buffer is allocated. */
				ba->prevfree = 0;

				/* Give user buffer starting at queue links. */
				buf =  (void *) &(b->ql);
				return buf;
			}
	    }
	    b = b->ql.flink;		  /* Link to next buffer */
	}

    return NULL;
}

/*  BGETZ  --  Allocate a buffer and clear its contents to zero.  We clear
	       the  entire  contents  of  the buffer to zero, not just the
	       region requested by the caller. */

void *bgetz(size)
  bufsize size;
{
    char *buf = (char *) bget(size);

    if (buf != NULL) {
		struct bhead *b;
		bufsize rsize;

		b = BH(buf - sizeof(struct bhead));
		rsize = -(b->bsize);

		rsize -= sizeof(struct bhead);

		assert(rsize >= size);
		V memset(buf, 0, (MemSize) rsize);
    }
    return ((void *) buf);
}

/*  BREL  --  Release a buffer.  */

void brel(buf)
  void *buf;
{
    struct bfhead *b, *bn;

    b = BFH(((char *) buf) - sizeof(struct bhead));
    assert(buf != NULL);

    /* Buffer size must be negative, indicating that the buffer is
       allocated. */

    if (b->bh.bsize >= 0) {
		bn = NULL;
    }
    assert(b->bh.bsize < 0);

    /*	Back pointer in next buffer must be zero, indicating the
	same thing: */

    assert(BH((char *) b - b->bh.bsize)->prevfree == 0);

    /* If the back link is nonzero, the previous buffer is free.  */

    if (b->bh.prevfree != 0) {

		/* The previous buffer is free.  Consolidate this buffer  with	it
		   by  adding  the  length  of	this  buffer  to the previous free
		   buffer.  Note that we subtract the size  in	the  buffer  being
			   released,  since  it's  negative to indicate that the buffer is
		   allocated. */

		register bufsize size = b->bh.bsize;

			/* Make the previous buffer the one we're working on. */
		assert(BH((char *) b - b->bh.prevfree)->bsize == b->bh.prevfree);
		b = BFH(((char *) b) - b->bh.prevfree);
		b->bh.bsize -= size;
	} else {

		/* The previous buffer isn't allocated.  Insert this buffer
	       on the free list as an isolated free block. */

		assert(nmm_flist->ql.blink->ql.flink == nmm_flist);
		assert(nmm_flist->ql.flink->ql.blink == nmm_flist);
		b->ql.flink = nmm_flist;
		b->ql.blink = nmm_flist->ql.blink;
		nmm_flist->ql.blink = b;
		b->ql.blink->ql.flink = b;
		b->bh.bsize = -b->bh.bsize;
    }

    /* Now we look at the next buffer in memory, located by advancing from
       the  start  of  this  buffer  by its size, to see if that buffer is
       free.  If it is, we combine  this  buffer  with	the  next  one	in
       memory, dechaining the second buffer from the free list. */

    bn =  BFH(((char *) b) + b->bh.bsize);
    if (bn->bh.bsize > 0) {

		/* The buffer is free.	Remove it from the free list and add
		   its size to that of our buffer. */

		assert(BH((char *) bn + bn->bh.bsize)->prevfree == bn->bh.bsize);
		assert(bn->ql.blink->ql.flink == bn);
		assert(bn->ql.flink->ql.blink == bn);
		bn->ql.blink->ql.flink = bn->ql.flink;
		bn->ql.flink->ql.blink = bn->ql.blink;
		b->bh.bsize += bn->bh.bsize;

		/* Finally,  advance  to   the	buffer	that   follows	the  newly
		   consolidated free block.  We must set its  backpointer  to  the
		   head  of  the  consolidated free block.  We know the next block
		   must be an allocated block because the process of recombination
		   guarantees  that  two  free	blocks will never be contiguous in
		   memory.  */

		bn = BFH(((char *) b) + b->bh.bsize);
    }
    assert(bn->bh.bsize < 0);

    /* The next buffer is allocated.  Set the backpointer in it  to  point
       to this buffer; the previous free buffer in memory. */

    bn->bh.prevfree = b->bh.bsize;
}

/*  BPOOL  --  Add a region of memory to the buffer pool.  */

void bpool(void *buf, bufsize len)
{
    struct bfhead *b = BFH(buf);
    struct bhead *bn;

#ifdef SizeQuant
    len &= ~(SizeQuant - 1);
#endif

    /* Since the block is initially occupied by a single free  buffer,
       it  had	better	not  be  (much) larger than the largest buffer
       whose size we can store in bhead.bsize. */

    assert(len - sizeof(struct bhead) <= -((bufsize) ESent + 1));

    /* Clear  the  backpointer at  the start of the block to indicate that
       there  is  no  free  block  prior  to  this   one.    That   blocks
       recombination when the first block in memory is released. */

    b->bh.prevfree = 0;

    /* Chain the new block to the free list. */

    assert(nmm_flist->ql.blink->ql.flink == nmm_flist);
    assert(nmm_flist->ql.flink->ql.blink == nmm_flist);
    b->ql.flink = nmm_flist;
    b->ql.blink = nmm_flist->ql.blink;
    nmm_flist->ql.blink = b;
    b->ql.blink->ql.flink = b;

    /* Create a dummy allocated buffer at the end of the pool.	This dummy
       buffer is seen when a buffer at the end of the pool is released and
       blocks  recombination  of  the last buffer with the dummy buffer at
       the end.  The length in the dummy buffer  is  set  to  the  largest
       negative  number  to  denote  the  end  of  the pool for diagnostic
       routines (this specific value is  not  counted  on  by  the  actual
       allocation and release functions). */

    len -= sizeof(struct bhead);
    b->bh.bsize = (bufsize) len;

	bn = BH(((char *) b) + len);
    bn->prevfree = (bufsize) len;
    /* Definition of ESent assumes two's complement! */
    assert((~0) == -1);
    bn->bsize = ESent;
}

void * nm_alloc(ulong_t size)
{
	void *ret;

	ret = bget(size);

	return ret;
}

EXPORT_SYMBOL(nm_alloc);



void nm_free(void *buf)
{
	brel(buf);
}

EXPORT_SYMBOL(nm_free);

/////////////////////////////////////////////////////
/* Authored by Hyunsub Song
 * NTL
 * Simple write/read mechanism for new memory storage
 */

/* void nm_write(unsigned long pfn, char __user *buf, size_t bytes)
{
	// Variables
	void *data_vaddr, *metadata_vaddr;
	struct nm_pfn_struct *nm_pfn;

	// Set metadata
	metadata_vaddr = bget(sizeof(*nm_pfn));
	nm_pfn = (struct nm_pfn_struct *) metadata_vaddr;

	// Set data
	data_vaddr = bget(bytes);

	// Fill nm_pfn_struct's attributes
	nm_pfn->pfn = pfn;
	nm_pfn->data_vaddr = data_vaddr;
	nm_pfn->bytes = bytes;
	INIT_LIST_HEAD(&nm_pfn->list);
	
    // Insert nm_pfn_struct in nm_pfn_list
	list_add(&nm_pfn->list, &nm_pfn_list);

	// Write data by memset()
	memcpy(data_vaddr, buf, bytes);

	printk(KERN_ALERT "nm_write() - pfn = 0x%x\n", nm_pfn->pfn);
	printk(KERN_ALERT "nm_write() - data_vaddr = 0x%x\n", nm_pfn->data_vaddr);
	printk(KERN_ALERT "nm_write() - bytes = %d\n", nm_pfn->bytes);
	printk(KERN_ALERT "nm_write() - buf = %s\n", buf);
}

EXPORT_SYMBOL(nm_write); */

/* For red-black tree */
/* void nm_write(unsigned long pfn, char __user *buf, size_t bytes)
{
	struct nm_pfn_struct *nm_pfn;
	
	nm_pfn = nm_rb_create(pfn, bytes);

	nm_rb_insert(&rb_root_tree, nm_pfn);

	memcpy(nm_pfn->data_vaddr, buf, nm_pfn->bytes);

	printk(KERN_ALERT "nm_write() - pfn = 0x%x\n", nm_pfn->pfn);
	printk(KERN_ALERT "nm_write() - data_vaddr = 0x%x\n", nm_pfn->data_vaddr);
	printk(KERN_ALERT "nm_write() - bytes = %d\n", nm_pfn->bytes);
	printk(KERN_ALERT "nm_write() - buf = %s\n", buf);

	// nm_rb_print(&rb_root_tree);
}

EXPORT_SYMBOL(nm_write); */

/* For radix-tree */

static size_t __nm_write(char *vaddr, const struct iovec *iov, size_t base, size_t bytes)
{
	size_t copied = 0, left = 0;

	while (bytes) {
		char __user *buf = iov->iov_base + base;
		int copy = min(bytes, iov->iov_len - base);

		base = 0;
		left = __copy_from_user_inatomic(vaddr, buf, copy);
		copied += copy;
		bytes -= copy;
		vaddr += copy;
		iov++;

		if (unlikely(left))
			break;
	}
	return copied - left;
}

size_t nm_write(unsigned long pfn, struct page *page, struct iov_iter *i, unsigned long offset, size_t bytes, struct radix_tree_root *rd_root, spinlock_t *tree_lock)
{
	char *kaddr;
	struct nm_pfn_struct *nm_pfn;
	size_t copied;

	nm_pfn = nm_rd_create(pfn, bytes);
	nm_rd_insert(nm_pfn, rd_root, tree_lock);

	BUG_ON(!in_atomic());
	kaddr = kmap_atomic(page);
	if (likely(i->nr_segs == 1)) {
		int left;
		char __user *buf = i->iov->iov_base + i->iov_offset;
		left = __copy_from_user(nm_pfn->data_vaddr, buf, nm_pfn->bytes);
		// left = __copy_from_user(kaddr + offset, buf, bytes);
		copied = bytes - left;
	} else {
		copied = __nm_write(nm_pfn->data_vaddr, i->iov, i->iov_offset, nm_pfn->bytes);
		// copied = __nm_write(kaddr + offset, i->iov, i->iov_offset, bytes);
	}
	kunmap_atomic(kaddr);

	

	
	// printk(KERN_ALERT "nm_write() - pfn = 0x%x\n", nm_pfn->pfn);
	// printk(KERN_ALERT "nm_write() - data_vaddr = 0x%x\n", nm_pfn->data_vaddr);
	// printk(KERN_ALERT "nm_write() - bytes = %d\n", nm_pfn->bytes);

	return copied;
}

EXPORT_SYMBOL(nm_write);

size_t nm_write_3(unsigned long pfn, struct bio *bio, struct radix_tree_root *rd_root, spinlock_t *tree_lock)
{
	struct nm_pfn_struct *nm_pfn;
	int left;
	size_t copied;
	nm_pfn = nm_rd_create(pfn, bio->bi_io_vec->bv_len);
	nm_rd_insert(nm_pfn, rd_root, tree_lock);
	left = __copy_from_user(nm_pfn->data_vaddr, page_address(bio->bi_io_vec->bv_page) + bio->bi_io_vec->bv_offset, nm_pfn->bytes);
	copied = nm_pfn->bytes - left;
	
	printk(KERN_ALERT "[sensong] nm_write() buf = %s\n", nm_pfn->data_vaddr);

	return copied;
}

EXPORT_SYMBOL(nm_write_3);

/* int nm_read(unsigned long pfn, read_descriptor_t *desc)
{
	// Find data through pfn
	struct nm_pfn_struct *nm_pfn;
	// char __user *tmp;
	unsigned long left;
	unsigned long size;

	list_for_each_entry(nm_pfn, &nm_pfn_list, list) {
		if (nm_pfn->pfn == pfn) {
			// tmp = kmalloc(nm_pfn->bytes, GFP_KERNEL);
            // memcpy(tmp, nm_pfn->data_vaddr, nm_pfn->bytes);
			// tmp = (char __user *) nm_pfn->data_vaddr;
			printk(KERN_ALERT "nm_read() - pfn = 0x%x\n", nm_pfn->pfn);
			printk(KERN_ALERT "nm_read() - data_vaddr = 0x%x\n", nm_pfn->data_vaddr);
			printk(KERN_ALERT "nm_read() - bytes = %d\n", nm_pfn->bytes);
			// printk(KERN_ALERT "nm_read() - tmp_buf = %s\n", tmp);
			left = __copy_to_user(desc->arg.buf, nm_pfn->data_vaddr, nm_pfn->bytes);
			if (left == 0) {
				desc->count -= nm_pfn->bytes;
				desc->written += nm_pfn->bytes;
				desc->arg.buf += nm_pfn->bytes;
				size = nm_pfn->bytes;
			}
		}
	}
	return size;
}

EXPORT_SYMBOL(nm_read); */

/* For red-black tree */
/* int nm_read(unsigned long pfn, read_descriptor_t *desc)
{
	struct nm_pfn_struct *nm_pfn;
	unsigned long left, size;

	nm_pfn = nm_rb_search(&rb_root_tree, pfn);
	printk(KERN_ALERT "nm_read() - pfn 0x%x\n", nm_pfn->pfn);
	printk(KERN_ALERT "nm_read() - data_vaddr = 0x%x\n", nm_pfn->data_vaddr);
	printk(KERN_ALERT "nm_read() - bytes = %d\n", nm_pfn->bytes);
		
	left = __copy_to_user(desc->arg.buf, nm_pfn->data_vaddr, nm_pfn->bytes);
	if (left == 0) {
		desc->count -= nm_pfn->bytes;
		desc->written += nm_pfn->bytes;
		desc->arg.buf += nm_pfn->bytes;
		size = nm_pfn->bytes;
	}
	
	return size;
}

EXPORT_SYMBOL(nm_read); */

/* For radix-tree */
int nm_read(unsigned long pfn, read_descriptor_t *desc, struct page *page, unsigned long offset, unsigned long size, struct radix_tree_root *rd_root)
{
	char *kaddr;
	struct nm_pfn_struct *nm_pfn;
	unsigned long left;
	unsigned long count;

	nm_pfn = nm_rd_search(pfn, rd_root);

	//printk(KERN_ALERT "nm_read() - pfn 0x%x\n", nm_pfn->pfn);
	//printk(KERN_ALERT "nm_read() - data_vaddr = 0x%x\n", nm_pfn->data_vaddr);
	//printk(KERN_ALERT "nm_read() - bytes = %d\n", nm_pfn->bytes);
	
	count = desc->count;

	if (size > count)
		size = count;

	if (!fault_in_pages_writeable(desc->arg.buf, size)) {
		kaddr = kmap_atomic(page);
		left = __copy_to_user_inatomic(desc->arg.buf, nm_pfn->data_vaddr, nm_pfn->bytes);
		// left = __copy_to_user_inatomic(desc->arg.buf, kaddr + offset, size);

		kunmap_atomic(kaddr);

		if (left == 0) 
			goto success;
	}
	
	kaddr = kmap(page);
	// left = __copy_to_user(desc->arg.buf, nm_pfn->data_vaddr, nm_pfn->bytes);
	left = __copy_to_user(desc->arg.buf, kaddr + offset, size);

	kunmap(page);

	if (left) {
		size -= left;
		desc->error = -EFAULT;
	}
	
success:
	desc->count = count - size;
	desc->written += size;
	desc->arg.buf += size;
	return size;
}

EXPORT_SYMBOL(nm_read);

/* For red-black tree */
/* struct nm_pfn_struct* nm_rb_create(unsigned long pfn, size_t bytes)
{
	void *data_vaddr, *metadata_vaddr;
	struct nm_pfn_struct* nm_pfn;
	
	metadata_vaddr = bget(sizeof(*nm_pfn));
	nm_pfn = (struct nm_pfn_struct *) metadata_vaddr;

	data_vaddr = bget(bytes);

	rb_init_node(&nm_pfn->node);
	nm_pfn->pfn = pfn;
	nm_pfn->data_vaddr = data_vaddr;
	nm_pfn->bytes = bytes;

	return nm_pfn;
}

struct nm_pfn_struct* __nm_rb_insert(struct rb_root *root, struct nm_pfn_struct *new_node)
{
	struct rb_node **new = &root->rb_node;
	struct rb_node *parent = NULL;
	struct nm_pfn_struct *this;

	while (*new)
	{
		parent = *new;
		this = rb_entry(parent, struct nm_pfn_struct, node);

		if (new_node->pfn < this->pfn) {
			printk(KERN_ALERT "__rb_insert: left, new->pfn = 0x%x\n", new_node->pfn);
			printk(KERN_ALERT "__rb_insert: left, this->pfn = 0x%x\n", this->pfn);
			printk(KERN_ALERT "__rb_insert: left, this->data_Vaddr = 0x%x\n", this->data_vaddr);
			new = &(*new)->rb_left;
		} else if (new_node->pfn > this->pfn) {
			printk(KERN_ALERT "__rb_insert: right, new->pfn = 0x%x\n", new_node->pfn);
			printk(KERN_ALERT "__rb_insert: right, this->pfn = 0x%x\n", this->pfn);
			printk(KERN_ALERT "__rb_insert: right, this->data_Vaddr = 0x%x\n", this->data_vaddr);
			new = &(*new)->rb_right;
		} else {
			printk(KERN_ALERT "__rb_insert: this\n");
			return this;
		}
	}
	rb_link_node(&new_node->node, parent, new);

	return NULL;
}

struct nm_pfn_struct* nm_rb_insert(struct rb_root *root, struct nm_pfn_struct *new_node)
{
	struct nm_pfn_struct *ret;
	if ((ret = __nm_rb_insert(root, new_node)))
		goto out;
	rb_insert_color(&new_node->node, root);
out:
	return ret;
}

struct nm_pfn_struct* nm_rb_search(struct rb_root *root, unsigned long pfn)
{
	struct rb_node *new = root->rb_node;
	struct nm_pfn_struct *this;

	while (new)
	{
		this = rb_entry(new, struct nm_pfn_struct, node);

		if (pfn < this->pfn)
			new = new->rb_left;
		else if (pfn > this->pfn)
			new = new->rb_right;
		else
			return this;
	}
	return NULL;
}

void __nm_rb_print(struct rb_node *tmp_node, int depth, int destination)
{
	struct nm_pfn_struct *this;
	this = rb_entry(tmp_node, struct nm_pfn_struct, node);
	int i;
	for (i = 0; i < depth; i++)
		printk(KERN_ALERT "\t");

	if (destination == 0)
		printk(KERN_ALERT "ROOT");
	else if (destination == 1)
		printk(KERN_ALERT "LEFT");
	else
		printk(KERN_ALERT "RIGHT");

	printk(KERN_ALERT "0x%x", this->pfn);
	printk(KERN_ALERT "0x%x", this->data_vaddr);
	printk(KERN_ALERT "0x%d\n", this->bytes);

	if (tmp_node->rb_left)
		__nm_rb_print(tmp_node->rb_left, depth + 1, 1);

	if (tmp_node->rb_right)
		__nm_rb_print(tmp_node->rb_right, depth + 1, 2);
}

void nm_rb_print(struct rb_root *root)
{
	struct rb_node *new = root->rb_node;
	__nm_rb_print(new, 1, 0);
} */

/* For radix-tree */
/* struct nm_pfn_struct* nm_rd_create(unsigned long pfn, size_t bytes)
{
	void *data_vaddr;
	struct nm_pfn_struct* nm_pfn;

	// metadata_vaddr = bget(sizeof(*nm_pfn));
	// nm_pfn = (struct nm_pfn_struct *) metadata_vaddr;
	nm_pfn = kmalloc(sizeof(*nm_pfn), GFP_KERNEL);

	// data_vaddr = bget(bytes);
	data_vaddr = kmalloc(bytes, GFP_KERNEL);

	nm_pfn->pfn = pfn;
	nm_pfn->data_vaddr = data_vaddr;
	nm_pfn->bytes = bytes;

	data_access_num++;
	printk(KERN_ALERT "sensong: nm_rd_create - data_access_num = %d\n", data_access_num);

	return nm_pfn;
} */

/* For radix-tree and fixed metadata */
struct nm_pfn_struct* nm_rd_create(unsigned long pfn, size_t bytes)
{
	void *data_vaddr;
	struct nm_pfn_struct* nm_pfn;
	
	// metadata_vaddr = bget(sizeof(*nm_pfn));
	// nm_pfn = (struct nm_pfn_struct *) metadata_vaddr;
	
	nm_pfn = kmalloc(sizeof(*nm_pfn), GFP_KERNEL);
	
	// nm_pfn = &(metadata_start_addr->nm_pfn[data_access_num]);

	// data_vaddr = bget(bytes);
	data_vaddr = kmalloc(bytes, GFP_KERNEL);

	nm_pfn->pfn = pfn;
	nm_pfn->data_vaddr = data_vaddr;
	nm_pfn->bytes = bytes;

	// data_access_num++;
	// printk(KERN_ALERT "sensong: nm_rd_create - data_access_num = %d\n", data_access_num);

	// return &(metadata_start_addr->nm_pfn[data_access_num - 1]);
	return nm_pfn;
}

void nm_rd_insert(struct nm_pfn_struct *new_node, struct radix_tree_root *rd_root, spinlock_t *tree_lock)
{
	spin_lock_irq(tree_lock);
	radix_tree_insert(rd_root, new_node->pfn, new_node);
	spin_unlock_irq(tree_lock);
	
	// b+ tree insert
	// int ret;

	// spin_lock_irq(tree_lock);
	// ret = btree_insert(&b_root, &btree_geo64, &(new_node->pfn), new_node, GFP_KERNEL);	
	// spin_unlock_irq(tree_lock);
}

struct nm_pfn_struct* nm_rd_search(unsigned long pfn, struct radix_tree_root *rd_root)
{
	struct nm_pfn_struct *nm_pfn;

	rcu_read_lock();
	nm_pfn = radix_tree_lookup(rd_root, pfn);
	rcu_read_unlock();
	
	// b+ tree search
	
	// printk(KERN_ALERT "nm_rd_search: pfn = 0x%x\n", pfn);
	
	// rcu_read_lock();
	// nm_pfn = btree_lookup(&b_root, &btree_geo64, &pfn);
	// rcu_read_unlock();

	return nm_pfn;
}
/////////////////////////////////////////////////////

struct list_head *get_nmm_lru_head(void)
{
	return &(manage_nm->nm_mng_header.lru_list);
}

EXPORT_SYMBOL(get_nmm_lru_head);


struct hlist_head *get_nmm_wcache_hashtable(void)
{
	return manage_nm->wcache_hashtable.hashtable;
}
EXPORT_SYMBOL(get_nmm_wcache_hashtable);


int *get_nmm_nr_caches(void)
{
	return &(manage_nm->nm_mng_header.nr_caches);
}

EXPORT_SYMBOL(get_nmm_nr_caches);

/*void nmm_test()
{
	printk(KERN_ALERT "[sensong]: nmm_test()\n");
}
EXPORT_SYMBOL(nmm_test); */

static int __init init_nm_nmm(void)
{	
	unsigned char *nm_vaddr, *start;
	// unsigned char *start;
	int i;

	/* Fixed metadata */
	// void *tmp_vaddr;

	/* For radix-tree */
	// INIT_RADIX_TREE(&rd_root, GFP_ATOMIC);
	
	/* For b+ tree */
	// btree_init(&b_root);	
	// spin_lock_init(&btree_lock);
	//////////////////////////////////////
	
	nm_vaddr = (unsigned char *) ioremap_nocache(NM_ADDR, NM_SIZE);
	// nm_vaddr = (unsigned char *) nm_ioremap_nocache(NM_ADDR, NM_SIZE);
	// nm_vaddr = (unsigned char *)vmalloc(NM_SIZE);
	// printk(KERN_ALERT "sensong: init_nm_nmm - nm_vaddr = 0x%x\n", nm_vaddr);

	manage_nm = (struct mm_nm *) nm_vaddr;

  	manage_nm->nm_start_vaddr = (unsigned int) nm_vaddr;

	nmm_flist = &(manage_nm->s_freelist);//

#ifdef CONFIG_DEBUG_NMM
	printk("init_nm: manage_nm 0x%x\n", (uint_t)manage_nm);
#endif

#ifdef CONFIG_INIT_NMM	
	memset(nm_vaddr, 0, NM_SIZE);

	// Only for NM init - for nm emul
	nmm_flist->bh.prevfree = 0;
	nmm_flist->bh.bsize = 0;
	nmm_flist->ql.flink = nmm_flist;
	nmm_flist->ql.blink = nmm_flist;

	INIT_LIST_HEAD(&(manage_nm->nm_mng_header.lru_list));

	// init hashtable for write cache
	spin_lock_init(&manage_nm->wcache_hashtable.hashtable_lock);
	for (i = 0; i < WCACHE_HASH_SIZE; i++)
	{
		INIT_HLIST_HEAD(&manage_nm->wcache_hashtable.hashtable[i]);
	}
	
	// Need to check 
	start = (unsigned int *)(manage_nm + 1); 

	bpool(start, (NM_SIZE - sizeof(*manage_nm)));

#ifdef CONFIG_DEBUG_NMM
	printk("init_nm: nm start 0x%x\n", (uint_t)start);
	printk("bpool(%x, %dK)\n", (unsigned int)start, (NM_SIZE - sizeof(*manage_nm))/1024);
#endif


#endif // CONFIG_INIT_NMM	

	/* Fixed metadata */
	// tmp_vaddr = bget(sizeof(*metadata_start_addr));
	// metadata_start_addr = (struct nm_pfn_struct_array *) tmp_vaddr;

	return 0;
}

static void __exit exit_nm_nmm(void)
{
	iounmap ((unsigned int *)manage_nm->nm_start_vaddr);
	// vfree(nm_vaddr);
}

module_init(init_nm_nmm)
module_exit(exit_nm_nmm)

MODULE_LICENSE("GPL");
