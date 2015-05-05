#
# Makefile for the linux ext5-filesystem routines.
#

obj-$(CONFIG_EXT5_FS) += ext5.o

ext5-y	:= balloc.o bitmap.o dir.o file.o fsync.o ialloc.o inode.o page-io.o \
		ioctl.o namei.o super.o symlink.o hash.o resize.o extents.o \
		ext5_jbd2.o migrate.o mballoc.o block_validity.o move_extent.o \
		mmp.o indirect.o extents_status.o xattr.o xattr_user.o \
		xattr_trusted.o inline.o

ext5-$(CONFIG_EXT5_FS_POSIX_ACL)	+= acl.o
ext5-$(CONFIG_EXT5_FS_SECURITY)		+= xattr_security.o
