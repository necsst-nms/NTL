/*
 *  linux/fs/ext5/bitmap.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 */

#include <linux/buffer_head.h>
#include <linux/jbd2.h>
#include "ext5.h"

unsigned int ext5_count_free(char *bitmap, unsigned int numchars)
{
	return numchars * BITS_PER_BYTE - memweight(bitmap, numchars);
}

int ext5_inode_bitmap_csum_verify(struct super_block *sb, ext5_group_t group,
				  struct ext5_group_desc *gdp,
				  struct buffer_head *bh, int sz)
{
	__u32 hi;
	__u32 provided, calculated;
	struct ext5_sb_info *sbi = EXT5_SB(sb);

	if (!EXT5_HAS_RO_COMPAT_FEATURE(sb,
					EXT5_FEATURE_RO_COMPAT_METADATA_CSUM))
		return 1;

	provided = le16_to_cpu(gdp->bg_inode_bitmap_csum_lo);
	calculated = ext5_chksum(sbi, sbi->s_csum_seed, (__u8 *)bh->b_data, sz);
	if (sbi->s_desc_size >= EXT5_BG_INODE_BITMAP_CSUM_HI_END) {
		hi = le16_to_cpu(gdp->bg_inode_bitmap_csum_hi);
		provided |= (hi << 16);
	} else
		calculated &= 0xFFFF;

	return provided == calculated;
}

void ext5_inode_bitmap_csum_set(struct super_block *sb, ext5_group_t group,
				struct ext5_group_desc *gdp,
				struct buffer_head *bh, int sz)
{
	__u32 csum;
	struct ext5_sb_info *sbi = EXT5_SB(sb);

	if (!EXT5_HAS_RO_COMPAT_FEATURE(sb,
					EXT5_FEATURE_RO_COMPAT_METADATA_CSUM))
		return;

	csum = ext5_chksum(sbi, sbi->s_csum_seed, (__u8 *)bh->b_data, sz);
	gdp->bg_inode_bitmap_csum_lo = cpu_to_le16(csum & 0xFFFF);
	if (sbi->s_desc_size >= EXT5_BG_INODE_BITMAP_CSUM_HI_END)
		gdp->bg_inode_bitmap_csum_hi = cpu_to_le16(csum >> 16);
}

int ext5_block_bitmap_csum_verify(struct super_block *sb, ext5_group_t group,
				  struct ext5_group_desc *gdp,
				  struct buffer_head *bh)
{
	__u32 hi;
	__u32 provided, calculated;
	struct ext5_sb_info *sbi = EXT5_SB(sb);
	int sz = EXT5_CLUSTERS_PER_GROUP(sb) / 8;

	if (!EXT5_HAS_RO_COMPAT_FEATURE(sb,
					EXT5_FEATURE_RO_COMPAT_METADATA_CSUM))
		return 1;

	provided = le16_to_cpu(gdp->bg_block_bitmap_csum_lo);
	calculated = ext5_chksum(sbi, sbi->s_csum_seed, (__u8 *)bh->b_data, sz);
	if (sbi->s_desc_size >= EXT5_BG_BLOCK_BITMAP_CSUM_HI_END) {
		hi = le16_to_cpu(gdp->bg_block_bitmap_csum_hi);
		provided |= (hi << 16);
	} else
		calculated &= 0xFFFF;

	if (provided == calculated)
		return 1;

	return 0;
}

void ext5_block_bitmap_csum_set(struct super_block *sb, ext5_group_t group,
				struct ext5_group_desc *gdp,
				struct buffer_head *bh)
{
	int sz = EXT5_CLUSTERS_PER_GROUP(sb) / 8;
	__u32 csum;
	struct ext5_sb_info *sbi = EXT5_SB(sb);

	if (!EXT5_HAS_RO_COMPAT_FEATURE(sb,
			EXT5_FEATURE_RO_COMPAT_METADATA_CSUM))
		return;

	csum = ext5_chksum(sbi, sbi->s_csum_seed, (__u8 *)bh->b_data, sz);
	gdp->bg_block_bitmap_csum_lo = cpu_to_le16(csum & 0xFFFF);
	if (sbi->s_desc_size >= EXT5_BG_BLOCK_BITMAP_CSUM_HI_END)
		gdp->bg_block_bitmap_csum_hi = cpu_to_le16(csum >> 16);
}
