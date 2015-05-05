/*
 * Resizable simple nm filesystem for Linux.
 *
 * Copyright (C) 2000 Linus Torvalds.
 *               2000 Transmeta Corp.
 *
 * Usage limits added by David Gibson, Linuxcare Australia.
 * This file is released under the GPL.
 */

/*
 * NOTE! This filesystem is probably most useful
 * not as a real filesystem, but as an example of
 * how virtual filesystems can be written.
 *
 * It doesn't get much simpler than this. Consider
 * that this file implements the full semantics of
 * a POSIX-compliant read-write filesystem.
 *
 * Note in particular how the filesystem does not
 * need to implement any data structures of its own
 * to keep track of the virtual data: using the VFS
 * caches is sufficient.
 */

#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/time.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/backing-dev.h>
#include <linux/nmfs.h>
#include <linux/sched.h>
#include <linux/parser.h>
#include <linux/magic.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
// #include <linux/nmm.h>
#include "internal.h"

#define RAMFS_DEFAULT_MODE	0755

static const struct super_operations nmfs_ops;
static const struct inode_operations nmfs_dir_inode_operations;

static struct backing_dev_info nmfs_backing_dev_info = {
	.name		= "nmfs",
	.ra_pages	= 0,	/* No readahead */
	.capabilities	= BDI_CAP_NO_ACCT_AND_WRITEBACK |
			  BDI_CAP_MAP_DIRECT | BDI_CAP_MAP_COPY |
			  BDI_CAP_READ_MAP | BDI_CAP_WRITE_MAP | BDI_CAP_EXEC_MAP,
};

struct inode *nmfs_get_inode(struct super_block *sb,
				const struct inode *dir, umode_t mode, dev_t dev)
{
	struct inode * inode = new_inode(sb);

	if (inode) {
		inode->i_ino = get_next_ino();
		inode_init_owner(inode, dir, mode);
		inode->i_mapping->a_ops = &nmfs_aops;
		inode->i_mapping->backing_dev_info = &nmfs_backing_dev_info;
		mapping_set_gfp_mask(inode->i_mapping, GFP_HIGHUSER);
		mapping_set_unevictable(inode->i_mapping);
		inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
		switch (mode & S_IFMT) {
		default:
			init_special_inode(inode, mode, dev);
			break;
		case S_IFREG:
			inode->i_op = &nmfs_file_inode_operations;
			inode->i_fop = &nmfs_file_operations;
			break;
		case S_IFDIR:
			inode->i_op = &nmfs_dir_inode_operations;
			inode->i_fop = &simple_dir_operations;

			/* directory inodes start off with i_nlink == 2 (for "." entry) */
			inc_nlink(inode);
			break;
		case S_IFLNK:
			inode->i_op = &page_symlink_inode_operations;
			break;
		}
	}
	return inode;
}

/*
 * File creation. Allocate an inode, and we're done..
 */
/* SMP-safe */
static int
nmfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
	struct inode * inode = nmfs_get_inode(dir->i_sb, dir, mode, dev);
	int error = -ENOSPC;

	if (inode) {
		d_instantiate(dentry, inode);
		dget(dentry);	/* Extra count - pin the dentry in core */
		error = 0;
		dir->i_mtime = dir->i_ctime = CURRENT_TIME;
	}
	return error;
}

static int nmfs_mkdir(struct inode * dir, struct dentry * dentry, umode_t mode)
{
	int retval = nmfs_mknod(dir, dentry, mode | S_IFDIR, 0);
	if (!retval)
		inc_nlink(dir);
	return retval;
}

static int nmfs_create(struct inode *dir, struct dentry *dentry, umode_t mode, bool excl)
{
	return nmfs_mknod(dir, dentry, mode | S_IFREG, 0);
}

static int nmfs_symlink(struct inode * dir, struct dentry *dentry, const char * symname)
{
	struct inode *inode;
	int error = -ENOSPC;

	inode = nmfs_get_inode(dir->i_sb, dir, S_IFLNK|S_IRWXUGO, 0);
	if (inode) {
		int l = strlen(symname)+1;
		error = page_symlink(inode, symname, l);
		if (!error) {
			d_instantiate(dentry, inode);
			dget(dentry);
			dir->i_mtime = dir->i_ctime = CURRENT_TIME;
		} else
			iput(inode);
	}
	return error;
}

static const struct inode_operations nmfs_dir_inode_operations = {
	.create		= nmfs_create,
	.lookup		= simple_lookup,
	.link		= simple_link,
	.unlink		= simple_unlink,
	.symlink	= nmfs_symlink,
	.mkdir		= nmfs_mkdir,
	.rmdir		= simple_rmdir,
	.mknod		= nmfs_mknod,
	.rename		= simple_rename,
};

static const struct super_operations nmfs_ops = {
	.statfs		= simple_statfs,
	.drop_inode	= generic_delete_inode,
	.show_options	= generic_show_options,
};

struct nmfs_mount_opts {
	umode_t mode;
};

enum {
	Opt_mode,
	Opt_err
};

static const match_table_t tokens = {
	{Opt_mode, "mode=%o"},
	{Opt_err, NULL}
};

struct nmfs_fs_info {
	struct nmfs_mount_opts mount_opts;
};

static int nmfs_parse_options(char *data, struct nmfs_mount_opts *opts)
{
	substring_t args[MAX_OPT_ARGS];
	int option;
	int token;
	char *p;

	opts->mode = RAMFS_DEFAULT_MODE;

	while ((p = strsep(&data, ",")) != NULL) {
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_mode:
			if (match_octal(&args[0], &option))
				return -EINVAL;
			opts->mode = option & S_IALLUGO;
			break;
		/*
		 * We might like to report bad mount options here;
		 * but traditionally nmfs has ignored all mount options,
		 * and as it is used as a !CONFIG_SHMEM simple substitute
		 * for tmpfs, better continue to ignore other mount options.
		 */
		}
	}

	return 0;
}

int nmfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct nmfs_fs_info *fsi;
	struct inode *inode;
	int err;

	save_mount_options(sb, data);

	fsi = kzalloc(sizeof(struct nmfs_fs_info), GFP_KERNEL);
	sb->s_fs_info = fsi;
	if (!fsi)
		return -ENOMEM;

	err = nmfs_parse_options(data, &fsi->mount_opts);
	if (err)
		return err;

	sb->s_maxbytes		= MAX_LFS_FILESIZE;
	sb->s_blocksize		= PAGE_CACHE_SIZE;
	sb->s_blocksize_bits	= PAGE_CACHE_SHIFT;
	sb->s_magic		= RAMFS_MAGIC;
	sb->s_op		= &nmfs_ops;
	sb->s_time_gran		= 1;

	inode = nmfs_get_inode(sb, NULL, S_IFDIR | fsi->mount_opts.mode, 0);
	sb->s_root = d_make_root(inode);
	if (!sb->s_root)
		return -ENOMEM;

	return 0;
}

struct dentry *nmfs_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	// nmm_test();
	return mount_nodev(fs_type, flags, data, nmfs_fill_super);
}

static struct dentry *nmrootfs_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return mount_nodev(fs_type, flags|MS_NOUSER, data, nmfs_fill_super);
}

static void nmfs_kill_sb(struct super_block *sb)
{
	kfree(sb->s_fs_info);
	kill_litter_super(sb);
}

static struct file_system_type nmfs_fs_type = {
	.name		= "nmfs",
	.mount		= nmfs_mount,
	.kill_sb	= nmfs_kill_sb,
	.fs_flags	= FS_USERNS_MOUNT,
};
static struct file_system_type nmrootfs_fs_type = {
	.name		= "nmrootfs",
	.mount		= nmrootfs_mount,
	.kill_sb	= kill_litter_super,
};

static int __init init_nmfs_fs(void)
{
	return register_filesystem(&nmfs_fs_type);
}
module_init(init_nmfs_fs)

int __init init_nmrootfs(void)
{
	int err;

	err = bdi_init(&nmfs_backing_dev_info);
	if (err)
		return err;

	err = register_filesystem(&nmrootfs_fs_type);
	if (err)
		bdi_destroy(&nmfs_backing_dev_info);

	return err;
}
