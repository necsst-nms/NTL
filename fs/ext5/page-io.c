/*
 * linux/fs/ext5/page-io.c
 *
 * This contains the new page_io functions for ext5
 *
 * Written by Theodore Ts'o, 2010.
 */

#include <linux/fs.h>
#include <linux/time.h>
#include <linux/jbd2.h>
#include <linux/highuid.h>
#include <linux/pagemap.h>
#include <linux/quotaops.h>
#include <linux/string.h>
#include <linux/buffer_head.h>
#include <linux/writeback.h>
#include <linux/pagevec.h>
#include <linux/mpage.h>
#include <linux/namei.h>
#include <linux/aio.h>
#include <linux/uio.h>
#include <linux/bio.h>
#include <linux/workqueue.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mm.h>

#include "ext5_jbd2.h"
#include "xattr.h"
#include "acl.h"

static struct kmem_cache *io_end_cachep;

int __init ext5_init_pageio(void)
{
	io_end_cachep = KMEM_CACHE(ext5_io_end, SLAB_RECLAIM_ACCOUNT);
	if (io_end_cachep == NULL)
		return -ENOMEM;
	return 0;
}

void ext5_exit_pageio(void)
{
	kmem_cache_destroy(io_end_cachep);
}

/*
 * This function is called by ext5_evict_inode() to make sure there is
 * no more pending I/O completion work left to do.
 */
void ext5_ioend_shutdown(struct inode *inode)
{
	wait_queue_head_t *wq = ext5_ioend_wq(inode);

	wait_event(*wq, (atomic_read(&EXT5_I(inode)->i_ioend_count) == 0));
	/*
	 * We need to make sure the work structure is finished being
	 * used before we let the inode get destroyed.
	 */
	if (work_pending(&EXT5_I(inode)->i_unwritten_work))
		cancel_work_sync(&EXT5_I(inode)->i_unwritten_work);
}

void ext5_free_io_end(ext5_io_end_t *io)
{
	BUG_ON(!io);
	BUG_ON(!list_empty(&io->list));
	BUG_ON(io->flag & EXT5_IO_END_UNWRITTEN);

	if (atomic_dec_and_test(&EXT5_I(io->inode)->i_ioend_count))
		wake_up_all(ext5_ioend_wq(io->inode));
	kmem_cache_free(io_end_cachep, io);
}

/* check a range of space and convert unwritten extents to written. */
static int ext5_end_io(ext5_io_end_t *io)
{
	struct inode *inode = io->inode;
	loff_t offset = io->offset;
	ssize_t size = io->size;
	int ret = 0;

	ext5_debug("ext5_end_io_nolock: io 0x%p from inode %lu,list->next 0x%p,"
		   "list->prev 0x%p\n",
		   io, inode->i_ino, io->list.next, io->list.prev);

	ret = ext5_convert_unwritten_extents(inode, offset, size);
	if (ret < 0) {
		ext5_msg(inode->i_sb, KERN_EMERG,
			 "failed to convert unwritten extents to written "
			 "extents -- potential data loss!  "
			 "(inode %lu, offset %llu, size %zd, error %d)",
			 inode->i_ino, offset, size, ret);
	}
	/* Wake up anyone waiting on unwritten extent conversion */
	if (atomic_dec_and_test(&EXT5_I(inode)->i_unwritten))
		wake_up_all(ext5_ioend_wq(inode));
	if (io->flag & EXT5_IO_END_DIRECT)
		inode_dio_done(inode);
	if (io->iocb)
		aio_complete(io->iocb, io->result, 0);
	return ret;
}

static void dump_completed_IO(struct inode *inode)
{
#ifdef	EXT5FS_DEBUG
	struct list_head *cur, *before, *after;
	ext5_io_end_t *io, *io0, *io1;

	if (list_empty(&EXT5_I(inode)->i_completed_io_list)) {
		ext5_debug("inode %lu completed_io list is empty\n",
			   inode->i_ino);
		return;
	}

	ext5_debug("Dump inode %lu completed_io list\n", inode->i_ino);
	list_for_each_entry(io, &EXT5_I(inode)->i_completed_io_list, list) {
		cur = &io->list;
		before = cur->prev;
		io0 = container_of(before, ext5_io_end_t, list);
		after = cur->next;
		io1 = container_of(after, ext5_io_end_t, list);

		ext5_debug("io 0x%p from inode %lu,prev 0x%p,next 0x%p\n",
			    io, inode->i_ino, io0, io1);
	}
#endif
}

/* Add the io_end to per-inode completed end_io list. */
void ext5_add_complete_io(ext5_io_end_t *io_end)
{
	struct ext5_inode_info *ei = EXT5_I(io_end->inode);
	struct workqueue_struct *wq;
	unsigned long flags;

	BUG_ON(!(io_end->flag & EXT5_IO_END_UNWRITTEN));
	wq = EXT5_SB(io_end->inode->i_sb)->dio_unwritten_wq;

	spin_lock_irqsave(&ei->i_completed_io_lock, flags);
	if (list_empty(&ei->i_completed_io_list))
		queue_work(wq, &ei->i_unwritten_work);
	list_add_tail(&io_end->list, &ei->i_completed_io_list);
	spin_unlock_irqrestore(&ei->i_completed_io_lock, flags);
}

static int ext5_do_flush_completed_IO(struct inode *inode)
{
	ext5_io_end_t *io;
	struct list_head unwritten;
	unsigned long flags;
	struct ext5_inode_info *ei = EXT5_I(inode);
	int err, ret = 0;

	spin_lock_irqsave(&ei->i_completed_io_lock, flags);
	dump_completed_IO(inode);
	list_replace_init(&ei->i_completed_io_list, &unwritten);
	spin_unlock_irqrestore(&ei->i_completed_io_lock, flags);

	while (!list_empty(&unwritten)) {
		io = list_entry(unwritten.next, ext5_io_end_t, list);
		BUG_ON(!(io->flag & EXT5_IO_END_UNWRITTEN));
		list_del_init(&io->list);

		err = ext5_end_io(io);
		if (unlikely(!ret && err))
			ret = err;
		io->flag &= ~EXT5_IO_END_UNWRITTEN;
		ext5_free_io_end(io);
	}
	return ret;
}

/*
 * work on completed aio dio IO, to convert unwritten extents to extents
 */
void ext5_end_io_work(struct work_struct *work)
{
	struct ext5_inode_info *ei = container_of(work, struct ext5_inode_info,
						  i_unwritten_work);
	ext5_do_flush_completed_IO(&ei->vfs_inode);
}

int ext5_flush_unwritten_io(struct inode *inode)
{
	int ret;
	WARN_ON_ONCE(!mutex_is_locked(&inode->i_mutex) &&
		     !(inode->i_state & I_FREEING));
	ret = ext5_do_flush_completed_IO(inode);
	ext5_unwritten_wait(inode);
	return ret;
}

ext5_io_end_t *ext5_init_io_end(struct inode *inode, gfp_t flags)
{
	ext5_io_end_t *io = kmem_cache_zalloc(io_end_cachep, flags);
	if (io) {
		atomic_inc(&EXT5_I(inode)->i_ioend_count);
		io->inode = inode;
		INIT_LIST_HEAD(&io->list);
	}
	return io;
}

/*
 * Print an buffer I/O error compatible with the fs/buffer.c.  This
 * provides compatibility with dmesg scrapers that look for a specific
 * buffer I/O error message.  We really need a unified error reporting
 * structure to userspace ala Digital Unix's uerf system, but it's
 * probably not going to happen in my lifetime, due to LKML politics...
 */
static void buffer_io_error(struct buffer_head *bh)
{
	char b[BDEVNAME_SIZE];
	printk(KERN_ERR "Buffer I/O error on device %s, logical block %llu\n",
			bdevname(bh->b_bdev, b),
			(unsigned long long)bh->b_blocknr);
}

static void ext5_end_bio(struct bio *bio, int error)
{
	ext5_io_end_t *io_end = bio->bi_private;
	struct inode *inode;
	int i;
	int blocksize;
	sector_t bi_sector = bio->bi_sector;

	BUG_ON(!io_end);
	inode = io_end->inode;
	blocksize = 1 << inode->i_blkbits;
	bio->bi_private = NULL;
	bio->bi_end_io = NULL;
	if (test_bit(BIO_UPTODATE, &bio->bi_flags))
		error = 0;
	for (i = 0; i < bio->bi_vcnt; i++) {
		struct bio_vec *bvec = &bio->bi_io_vec[i];
		struct page *page = bvec->bv_page;
		struct buffer_head *bh, *head;
		unsigned bio_start = bvec->bv_offset;
		unsigned bio_end = bio_start + bvec->bv_len;
		unsigned under_io = 0;
		unsigned long flags;

		if (!page)
			continue;

		if (error) {
			SetPageError(page);
			set_bit(AS_EIO, &page->mapping->flags);
		}
		bh = head = page_buffers(page);
		/*
		 * We check all buffers in the page under BH_Uptodate_Lock
		 * to avoid races with other end io clearing async_write flags
		 */
		local_irq_save(flags);
		bit_spin_lock(BH_Uptodate_Lock, &head->b_state);
		do {
			if (bh_offset(bh) < bio_start ||
			    bh_offset(bh) + blocksize > bio_end) {
				if (buffer_async_write(bh))
					under_io++;
				continue;
			}
			clear_buffer_async_write(bh);
			if (error)
				buffer_io_error(bh);
		} while ((bh = bh->b_this_page) != head);
		bit_spin_unlock(BH_Uptodate_Lock, &head->b_state);
		local_irq_restore(flags);
		if (!under_io)
			end_page_writeback(page);
	}
	bio_put(bio);

	if (error) {
		io_end->flag |= EXT5_IO_END_ERROR;
		ext5_warning(inode->i_sb, "I/O error writing to inode %lu "
			     "(offset %llu size %ld starting block %llu)",
			     inode->i_ino,
			     (unsigned long long) io_end->offset,
			     (long) io_end->size,
			     (unsigned long long)
			     bi_sector >> (inode->i_blkbits - 9));
	}

	if (!(io_end->flag & EXT5_IO_END_UNWRITTEN)) {
		ext5_free_io_end(io_end);
		return;
	}

	ext5_add_complete_io(io_end);
}

void ext5_io_submit(struct ext5_io_submit *io)
{
	struct bio *bio = io->io_bio;

	if (bio) {
		bio_get(io->io_bio);
		submit_bio(io->io_op, io->io_bio);
		BUG_ON(bio_flagged(io->io_bio, BIO_EOPNOTSUPP));
		bio_put(io->io_bio);
	}
	io->io_bio = NULL;
	io->io_op = 0;
	io->io_end = NULL;
}

static int io_submit_init(struct ext5_io_submit *io,
			  struct inode *inode,
			  struct writeback_control *wbc,
			  struct buffer_head *bh)
{
	ext5_io_end_t *io_end;
	struct page *page = bh->b_page;
	int nvecs = bio_get_nr_vecs(bh->b_bdev);
	struct bio *bio;

	io_end = ext5_init_io_end(inode, GFP_NOFS);
	if (!io_end)
		return -ENOMEM;
	bio = bio_alloc(GFP_NOIO, min(nvecs, BIO_MAX_PAGES));
	bio->bi_sector = bh->b_blocknr * (bh->b_size >> 9);
	bio->bi_bdev = bh->b_bdev;
	bio->bi_private = io->io_end = io_end;
	bio->bi_end_io = ext5_end_bio;

	io_end->offset = (page->index << PAGE_CACHE_SHIFT) + bh_offset(bh);

	io->io_bio = bio;
	io->io_op = (wbc->sync_mode == WB_SYNC_ALL ?  WRITE_SYNC : WRITE);
	io->io_next_block = bh->b_blocknr;
	return 0;
}

static int io_submit_add_bh(struct ext5_io_submit *io,
			    struct inode *inode,
			    struct writeback_control *wbc,
			    struct buffer_head *bh)
{
	ext5_io_end_t *io_end;
	int ret;

	if (io->io_bio && bh->b_blocknr != io->io_next_block) {
submit_and_retry:
		ext5_io_submit(io);
	}
	if (io->io_bio == NULL) {
		ret = io_submit_init(io, inode, wbc, bh);
		if (ret)
			return ret;
	}
	io_end = io->io_end;
	if (test_clear_buffer_uninit(bh))
		ext5_set_io_unwritten_flag(inode, io_end);
	io->io_end->size += bh->b_size;
	io->io_next_block++;
	ret = bio_add_page(io->io_bio, bh->b_page, bh->b_size, bh_offset(bh));
	if (ret != bh->b_size)
		goto submit_and_retry;
	return 0;
}

int ext5_bio_write_page(struct ext5_io_submit *io,
			struct page *page,
			int len,
			struct writeback_control *wbc)
{
	struct inode *inode = page->mapping->host;
	unsigned block_start, blocksize;
	struct buffer_head *bh, *head;
	int ret = 0;
	int nr_submitted = 0;

	blocksize = 1 << inode->i_blkbits;

	BUG_ON(!PageLocked(page));
	BUG_ON(PageWriteback(page));

	set_page_writeback(page);
	ClearPageError(page);

	/*
	 * In the first loop we prepare and mark buffers to submit. We have to
	 * mark all buffers in the page before submitting so that
	 * end_page_writeback() cannot be called from ext5_bio_end_io() when IO
	 * on the first buffer finishes and we are still working on submitting
	 * the second buffer.
	 */
	bh = head = page_buffers(page);
	do {
		block_start = bh_offset(bh);
		if (block_start >= len) {
			/*
			 * Comments copied from block_write_full_page_endio:
			 *
			 * The page straddles i_size.  It must be zeroed out on
			 * each and every writepage invocation because it may
			 * be mmapped.  "A file is mapped in multiples of the
			 * page size.  For a file that is not a multiple of
			 * the  page size, the remaining memory is zeroed when
			 * mapped, and writes to that region are not written
			 * out to the file."
			 */
			zero_user_segment(page, block_start,
					  block_start + blocksize);
			clear_buffer_dirty(bh);
			set_buffer_uptodate(bh);
			continue;
		}
		if (!buffer_dirty(bh) || buffer_delay(bh) ||
		    !buffer_mapped(bh) || buffer_unwritten(bh)) {
			/* A hole? We can safely clear the dirty bit */
			if (!buffer_mapped(bh))
				clear_buffer_dirty(bh);
			if (io->io_bio)
				ext5_io_submit(io);
			continue;
		}
		if (buffer_new(bh)) {
			clear_buffer_new(bh);
			unmap_underlying_metadata(bh->b_bdev, bh->b_blocknr);
		}
		set_buffer_async_write(bh);
	} while ((bh = bh->b_this_page) != head);

	/* Now submit buffers to write */
	bh = head = page_buffers(page);
	do {
		if (!buffer_async_write(bh))
			continue;
		ret = io_submit_add_bh(io, inode, wbc, bh);
		if (ret) {
			/*
			 * We only get here on ENOMEM.  Not much else
			 * we can do but mark the page as dirty, and
			 * better luck next time.
			 */
			redirty_page_for_writepage(wbc, page);
			break;
		}
		nr_submitted++;
		clear_buffer_dirty(bh);
	} while ((bh = bh->b_this_page) != head);

	/* Error stopped previous loop? Clean up buffers... */
	if (ret) {
		do {
			clear_buffer_async_write(bh);
			bh = bh->b_this_page;
		} while (bh != head);
	}
	unlock_page(page);
	/* Nothing submitted - we have to end page writeback */
	if (!nr_submitted)
		end_page_writeback(page);
	return ret;
}
