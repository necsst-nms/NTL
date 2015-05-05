/*
 *  fs/ext5/mballoc.h
 *
 *  Written by: Alex Tomas <alex@clusterfs.com>
 *
 */
#ifndef _EXT5_MBALLOC_H
#define _EXT5_MBALLOC_H

#include <linux/time.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/quotaops.h>
#include <linux/buffer_head.h>
#include <linux/module.h>
#include <linux/swap.h>
#include <linux/proc_fs.h>
#include <linux/pagemap.h>
#include <linux/seq_file.h>
#include <linux/blkdev.h>
#include <linux/mutex.h>
#include "ext5_jbd2.h"
#include "ext5.h"

/*
 * with AGGRESSIVE_CHECK allocator runs consistency checks over
 * structures. these checks slow things down a lot
 */
#define AGGRESSIVE_CHECK__

/*
 * with DOUBLE_CHECK defined mballoc creates persistent in-core
 * bitmaps, maintains and uses them to check for double allocations
 */
#define DOUBLE_CHECK__

/*
 */
#ifdef CONFIG_EXT5_DEBUG
extern ushort ext5_mballoc_debug;

#define mb_debug(n, fmt, a...)	                                        \
	do {								\
		if ((n) <= ext5_mballoc_debug) {		        \
			printk(KERN_DEBUG "(%s, %d): %s: ",		\
			       __FILE__, __LINE__, __func__);		\
			printk(fmt, ## a);				\
		}							\
	} while (0)
#else
#define mb_debug(n, fmt, a...)
#endif

#define EXT5_MB_HISTORY_ALLOC		1	/* allocation */
#define EXT5_MB_HISTORY_PREALLOC	2	/* preallocated blocks used */

/*
 * How long mballoc can look for a best extent (in found extents)
 */
#define MB_DEFAULT_MAX_TO_SCAN		200

/*
 * How long mballoc must look for a best extent
 */
#define MB_DEFAULT_MIN_TO_SCAN		10

/*
 * with 'ext5_mb_stats' allocator will collect stats that will be
 * shown at umount. The collecting costs though!
 */
#define MB_DEFAULT_STATS		0

/*
 * files smaller than MB_DEFAULT_STREAM_THRESHOLD are served
 * by the stream allocator, which purpose is to pack requests
 * as close each to other as possible to produce smooth I/O traffic
 * We use locality group prealloc space for stream request.
 * We can tune the same via /proc/fs/ext5/<parition>/stream_req
 */
#define MB_DEFAULT_STREAM_THRESHOLD	16	/* 64K */

/*
 * for which requests use 2^N search using buddies
 */
#define MB_DEFAULT_ORDER2_REQS		2

/*
 * default group prealloc size 512 blocks
 */
#define MB_DEFAULT_GROUP_PREALLOC	512


struct ext5_free_data {
	/* MUST be the first member */
	struct ext5_journal_cb_entry	efd_jce;

	/* ext5_free_data private data starts from here */

	/* this links the free block information from group_info */
	struct rb_node			efd_node;

	/* group which free block extent belongs */
	ext5_group_t			efd_group;

	/* free block extent */
	ext5_grpblk_t			efd_start_cluster;
	ext5_grpblk_t			efd_count;

	/* transaction which freed this extent */
	tid_t				efd_tid;
};

struct ext5_prealloc_space {
	struct list_head	pa_inode_list;
	struct list_head	pa_group_list;
	union {
		struct list_head pa_tmp_list;
		struct rcu_head	pa_rcu;
	} u;
	spinlock_t		pa_lock;
	atomic_t		pa_count;
	unsigned		pa_deleted;
	ext5_fsblk_t		pa_pstart;	/* phys. block */
	ext5_lblk_t		pa_lstart;	/* log. block */
	ext5_grpblk_t		pa_len;		/* len of preallocated chunk */
	ext5_grpblk_t		pa_free;	/* how many blocks are free */
	unsigned short		pa_type;	/* pa type. inode or group */
	spinlock_t		*pa_obj_lock;
	struct inode		*pa_inode;	/* hack, for history only */
};

enum {
	MB_INODE_PA = 0,
	MB_GROUP_PA = 1
};

struct ext5_free_extent {
	ext5_lblk_t fe_logical;
	ext5_grpblk_t fe_start;	/* In cluster units */
	ext5_group_t fe_group;
	ext5_grpblk_t fe_len;	/* In cluster units */
};

/*
 * Locality group:
 *   we try to group all related changes together
 *   so that writeback can flush/allocate them together as well
 *   Size of lg_prealloc_list hash is determined by MB_DEFAULT_GROUP_PREALLOC
 *   (512). We store prealloc space into the hash based on the pa_free blocks
 *   order value.ie, fls(pa_free)-1;
 */
#define PREALLOC_TB_SIZE 10
struct ext5_locality_group {
	/* for allocator */
	/* to serialize allocates */
	struct mutex		lg_mutex;
	/* list of preallocations */
	struct list_head	lg_prealloc_list[PREALLOC_TB_SIZE];
	spinlock_t		lg_prealloc_lock;
};

struct ext5_allocation_context {
	struct inode *ac_inode;
	struct super_block *ac_sb;

	/* original request */
	struct ext5_free_extent ac_o_ex;

	/* goal request (normalized ac_o_ex) */
	struct ext5_free_extent ac_g_ex;

	/* the best found extent */
	struct ext5_free_extent ac_b_ex;

	/* copy of the best found extent taken before preallocation efforts */
	struct ext5_free_extent ac_f_ex;

	/* number of iterations done. we have to track to limit searching */
	unsigned long ac_ex_scanned;
	__u16 ac_groups_scanned;
	__u16 ac_found;
	__u16 ac_tail;
	__u16 ac_buddy;
	__u16 ac_flags;		/* allocation hints */
	__u8 ac_status;
	__u8 ac_criteria;
	__u8 ac_2order;		/* if request is to allocate 2^N blocks and
				 * N > 0, the field stores N, otherwise 0 */
	__u8 ac_op;		/* operation, for history only */
	struct page *ac_bitmap_page;
	struct page *ac_buddy_page;
	struct ext5_prealloc_space *ac_pa;
	struct ext5_locality_group *ac_lg;
};

#define AC_STATUS_CONTINUE	1
#define AC_STATUS_FOUND		2
#define AC_STATUS_BREAK		3

struct ext5_buddy {
	struct page *bd_buddy_page;
	void *bd_buddy;
	struct page *bd_bitmap_page;
	void *bd_bitmap;
	struct ext5_group_info *bd_info;
	struct super_block *bd_sb;
	__u16 bd_blkbits;
	ext5_group_t bd_group;
};

static inline ext5_fsblk_t ext5_grp_offs_to_block(struct super_block *sb,
					struct ext5_free_extent *fex)
{
	return ext5_group_first_block_no(sb, fex->fe_group) +
		(fex->fe_start << EXT5_SB(sb)->s_cluster_bits);
}
#endif
