#
# Makefile for the linux nmfs routines.
#

obj-y += nmm.o
obj-y += nmfs.o

file-mmu-y := file-nommu.o
file-mmu-$(CONFIG_MMU) := file-mmu.o
nmfs-objs += inode.o $(file-mmu-y)
