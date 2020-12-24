#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/utime.h>

#include "types.h"
#include "misc.h"
#include "util.h"
#include "kgen.h"
#include "aes.h"
#include "aes_xts.h"
#include "misc.h"
#include "fs/ufs/dinode.h"
#include "fs/ufs/fs.h"
#include "fs/ufs/dir.h"
#include "fs/ufs/ps3.h"
#include "fs/fat/fat.h"

#ifdef _WIN32
#include <io.h>
#include "getopt.h"
#else
#include <unistd.h>
#include <getopt.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define _fseeki64 fseeko64 
#define _ftelli64 ftello64

#ifdef __cplusplus
}
#endif

// #define OUTBIN "out.bin"
#define SECTOR_SIZE 0x200
#define BUFFER_SIZE 0x100000


/* proto */
time_t fat2unix_time(u16 time, u16 date);


/* device stuff */
HANDLE get_hdd_handle();
HANDLE get_file_handle();
int get_partitions(HANDLE device);
s64 read_device(HANDLE device, u8 *buf, u64 numbytes, u64 dev_off);
int ufs_read_device(HANDLE device, u8 *buf, u64 numbytes, int dev_sec);
// s64 block_read(HANDLE device, u8 *buf, s64 n_sec, s64 sec_num);
s64 block_write(HANDLE device, u8 *buf, s64 n_sec, s64 sec_num);
s64 write_device(HANDLE device, u8 *buf, u64 numbytes, s64 dev_off);
void print_volume_info(HANDLE device, const char *name);


/* fat stuff */
// int mkdir(const char *pathname, mode_t mode);
struct fat_bs* init_fat_old(HANDLE device, u64 start);
struct fat32_bs* init_fat32(HANDLE device, u64 start);
int get_fat_type(struct fat_bs *fat);
u64 fat_how_free_bytes(HANDLE device, u64 storage, struct fat_bs *fat, struct fat32_bs *fat32);
fat_clu_list* fat_get_cluster_list(HANDLE device, u64 storage, struct fat_bs *fat_fs, struct fat32_bs *fat32, fat_add_t cluster);
void fat_free_cluster_list(fat_clu_list *list);
int fat_read_cluster(HANDLE device, u64 storage, struct fat_bs *fat_fs, struct fat32_bs *fat32, fat_clu_list *list, u8 *buf, u32 start, u32 count);
int fat_get_entry_count(u8 *clusters);
int get_lfn_name(u8 *tmp, char part[M_LFN_LENGTH]);
int get_sfn_name(u8 *sfn_name, u8* name);
int fat_dir_search_entry(u8 *cluster, u8 *s_name, u8 *tmp);
struct sfn_e* fat_lookup_path(HANDLE device, u64 storage, struct fat_bs *fat_fs, struct fat32_bs *fat32, u8 *path, fat_add_t fat_root);
int fat_get_entries(u8 *buf, struct fat_dir_entry *dirs);
int sort_dir(const void *first, const void *second);
struct date_time fat_datetime_from_entry(u16 date, u16 time);
int fat_print_dir_list(HANDLE device, u64 storage, struct fat_bs *fat_fs, struct fat32_bs *fat32, u8 *path, u8 *volume, u64 free_byte);
int fat_copy_data(HANDLE device, u64 storage, struct fat_bs *fat_fs, struct fat32_bs *fat32, char *srcpath, char *destpath);


/* ufs stuff */
struct fs* ufs2_init(HANDLE device);
int ufs_read_direntry(void *buf, struct direct* dir);
void ufs_free_block_list(ufs2_block_list *list);
int ufs_sort_dir(const void *first, const void *second);
int ufs_read_data(HANDLE device, struct fs *fs, struct ufs2_dinode *di, ufs2_block_list *block_list, u8 *buf, ufs_inop start_block, ufs_inop num_blocks);
ufs2_block_list* get_block_list(HANDLE device, struct fs *ufs2, struct ufs2_dinode *di);
int read_inode(HANDLE device, struct fs *fs, ufs_inop ino, struct ufs2_dinode *di);
ufs_inop ufs_lookup_path(HANDLE device, struct fs* ufs2, u8* path, int follow, ufs_inop root_ino);
int ufs_print_dir_list(HANDLE device, struct fs *ufs2, u8 *path, u8 *volume);
int ufs_copy_data(HANDLE device, struct fs *ufs2, ufs_inop root_ino, ufs_inop ino, char *srcpath, char *destpath);
s32 ufs_replace_data(HANDLE device, struct fs *ufs2, ufs_inop root_ino, ufs_inop ino, char *path);


/* glob */
static u8 ata_k1[0x20] = {0};
static u8 ata_k2[0x20] = {0};
static u8 encdec_key1[0x20] = {0};
static u8 encdec_key2[0x20] = {0};
static u8 iv[0x10] = {0};
static u8 ps3_type = 0;	/*!	ps3 type:	1 = FAT_NAND(ata: aes-cbc-192 / no vflash)
										2 = FAT_NOR (ata: aes-cbc-192 / vflash: aes-xts-128)
										3 = SLIM_NOR(ata: aes-xts-128 / vflash: aes-xts-128)*/
static u64 vflash_start	= 0;// vflash
static u64 vflash_size  = 0;
static u64 hdd0_start 	= 0;// gameOS(UFS2)
static u64 hdd0_size  	= 0;
static u64 hdd1_start 	= 0;// gameOS/swap(FAT32)
static u64 hdd1_size  	= 0;
static u64 hdd1_free  	= 0;
static u64 flash_start 	= 0;// vflash 2(FAT16)
static u64 flash_size 	= 0;
static u64 flash_free 	= 0;
static u64 flash2_start = 0;// vflash 3(FAT16)
static u64 flash2_size 	= 0;
static u64 flash2_free 	= 0;
static u64 flash3_start = 0;// vflash 4(FAT12)
static u64 flash3_size 	= 0;
static u64 flash3_free 	= 0;
#ifdef DUMP
void decrypt_all_sectors(const s8 *out_file, const s8 *in_file, u64 start_sector, u64 num_sectors, u8 *ata_k1, u8 *ata_k2, u8 *edec_k1, u8 *edec_k2, BOOL is_phat, BOOL is_vflash);
#endif


/***********************************************************************
*function: fat2unix_time, konvertiert FAT time/date paar zu unix-time
* 	u16 time = FAT time
* 	u16 date = FAT date
* (from linux-kernel)
***********************************************************************/
time_t fat2unix_time(u16 time, u16 date)
{
  time_t second, day, leap_day, month, year;
	
	
  year  = date >> 9;
  month = max(1, (date >> 5) & 0xf);
  day   = max(1, date & 0x1f) - 1;

  leap_day = (year + 3) / 4;
  
  if(year > YEAR_2100)
		leap_day--;
		
	if(IS_LEAP_YEAR(year) && month > 2)
		leap_day++;

	second =  (time & 0x1f) << 1;
	second += ((time >> 5) & 0x3f) * SECS_PER_MIN;
	second += (time >> 11) * SECS_PER_HOUR;
	second += (year * 365 + leap_day + days_in_year[month] + day + DAYS_DELTA) * SECS_PER_DAY;
		
	return second;
}

/*! print usage */
void usage(){
	printf("\nPS3 HDD Reader for Windows, ver. 1.0, free no (c) \n\n");
	// printf("This tool can read and dump file(s)/folder(s) from a ps3_hdd. It need\n");
	// printf("a per-console key-file called \"eid_root_key\" to decrypt the ps3_hdd.\n");
	// printf("Search the net for infos about this key and how you can obtain him.\n\n");
	printf("\n\n");
	printf("usage: ");
	printf(" ps3 <source> <volume> <command> <path>\n\n");
	printf(" source: hdd  (reading from a ps3_hdd.)\n");
	printf("         file (reading from a byte-exact backup_file of a ps3_hdd.\n");
	printf("               backup must called \"backup.img\" and be in program-folder.\n");
	printf("               NO support for backups created with the \"PS3 Backup Utility\"!)\n\n");
	printf(" volume: dev_hdd0, dev_hdd1 (NAND console),\n");
	printf("         dev_hdd0, dev_hdd1, dev_flash, dev_flash2, dev_flash3 (NOR console)\n\n");
	printf(" command: dir or ls  (show the content of a directory)\n");
	printf("          copy or cp (copy file(s)/folder(s) to program-folder)\n\n");
	printf(" path: path to show or copy (all paths must begin in root)\n");
	printf("       (if your path contain spaces, put double quotes around the path)\n\n");
	printf("example:\n\n ps3 hdd dev_hdd0 dir /\n (list the root-dir of dev_hdd0(gameOS))\n\n");
	printf(" ps3 hdd dev_flash2 cp /etc/xRegistry.sys\n (copy file xRegistry.sys to program-folder)\n\n");
	// printf("Credits goes to ALL involved! Specially to Graf, Glevand, Naehrwert, Flatz\n");
	// printf("and all helper/tester from ps3hax.net. \n");
	printf("\n");
}

void print_volume_info(HANDLE device, const char *name)
{
	printf("\nvolume %s information:\n\n", name);
	
	if(strcmp(name, "dev_hdd0") == 0) {
		printf("start sector: 0x%016llX\n", hdd0_start);
		printf("sector count: 0x%016llX\n", hdd0_size);
		
	}
	if(strcmp(name, "dev_hdd1") == 0) {
		printf("start sector: 0x%016llX\n", hdd1_start);
		printf("sector count: 0x%016llX\n", hdd1_size);
		
	}
	if(strcmp(name, "dev_flash") == 0) {
		printf("start sector: 0x%016llX\n", flash_start);
		printf("sector count: 0x%016llX\n", flash_size);
		
	}
	if(strcmp(name, "dev_flash2") == 0) {
		printf("start sector: 0x%016llX\n", flash2_start);
		printf("sector count: 0x%016llX\n", flash2_size);
		
	}
	if(strcmp(name, "dev_flash3") == 0) {
		printf("start sector: 0x%016llX\n", flash3_start);
		printf("sector count: 0x%016llX\n", flash3_size);
		
	}
}


/* device stuff */
/***********************************************************************
*get handle on hdd and ps3 typ
***********************************************************************/
HANDLE get_hdd_handle()
{
	int i;
	u64 sqnr = 0;
	char drive[32];		
	struct disklabel *ps3_pt;	
	DWORD read = 0;		
	HANDLE device;	
	u8 *buf = malloc(SECTOR_SIZE);	
	u8 *tmp = malloc(SECTOR_SIZE);	
	aes_xts_ctxt_t xts_ctx;	
	aes_context cbc_ctx;	
	
	
	for(i = 1; i < 16; i++){
		sprintf(drive, "\\\\.\\PhysicalDrive%d", i);
		
		device = CreateFile(drive, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
		
		if(device == INVALID_HANDLE_VALUE)
		{
			CloseHandle(device);
			continue;
		}
		else
		{
			seek_device(device, 0);
			ReadFile(device, buf, SECTOR_SIZE * 1, &read, 0);
			_es16_buffer(buf, SECTOR_SIZE * 1);
			
			// test aes_cbc_192
			memcpy(tmp, buf, SECTOR_SIZE);
			aes_setkey_dec(&cbc_ctx, ata_k1, 192);
			aes_crypt_cbc(&cbc_ctx, AES_DECRYPT, SECTOR_SIZE, iv, tmp, tmp);
			memset(iv, 0, 16);
			ps3_pt = (struct disklabel *)tmp;
		
			// HDD is FAT
			if(_ES64(ps3_pt->d_magic1) == MAGIC1 && _ES64(ps3_pt->d_magic2) == MAGIC2){
				// get first sector of first region
				u64 start = _ES64(ps3_pt->d_partitions[0].p_start);
				seek_device(device, start * SECTOR_SIZE);
				ReadFile(device, buf, SECTOR_SIZE, &read, 0);
				_es16_buffer(buf, SECTOR_SIZE);
				
				// decrypt layer_1, ata(aes_cbc_192)
				aes_setkey_dec(&cbc_ctx, ata_k1, 192);
				aes_crypt_cbc(&cbc_ctx, AES_DECRYPT, SECTOR_SIZE, iv, buf, buf);
				memset(iv, 0, 16);
			  
				// decrypt layer_2, vflash(aes-xts-128)
				aes_xts_init(&xts_ctx, AES_DECRYPT, encdec_key1, encdec_key2, 128);
				aes_xts_crypt(&xts_ctx, 8, SECTOR_SIZE, buf, buf);
				
				ps3_pt = (struct disklabel *)buf;
				
				// if first region had a partition table, it must be vflash, so its a Fat NOR
				if(_ES64(ps3_pt->d_magic1) == MAGIC1 && _ES64(ps3_pt->d_magic2) == MAGIC2)
					ps3_type = 2;
				else
				  ps3_type = 1;
				
				free(ps3_pt);
				free(tmp);
				return device;
			}
			
			// test aes_xts_128
			memcpy(tmp, buf, SECTOR_SIZE);
			aes_xts_init(&xts_ctx, AES_DECRYPT, ata_k1, ata_k2, 128);
			aes_xts_crypt(&xts_ctx, sqnr, SECTOR_SIZE, tmp, tmp);
			ps3_pt = (struct disklabel *)tmp;
		
			if(_ES64(ps3_pt->d_magic1) == MAGIC1 && _ES64(ps3_pt->d_magic2) == MAGIC2){
				ps3_type = 3;
				free(ps3_pt);
				free(buf);
				return device;
			}
		}
	}
	free(tmp);
	free(buf);
	printf("no hdd(s) found !\n");
	return NULL;
}
/*! get handle on backup-file and ps3 typ */
HANDLE get_file_handle()
{
	u64 sqnr = 0;
	struct disklabel *ps3_pt;	
	DWORD read = 0;		
	HANDLE device;	
	// FILE *out;
	// char out_file;
	// u64 chunk_size=0;
	u8 *buf = malloc(SECTOR_SIZE);	
	u8 *tmp = malloc(SECTOR_SIZE);	
	aes_xts_ctxt_t xts_ctx;	
	aes_context cbc_ctx;		
	device = CreateFile("backup.img", GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
	if(device == INVALID_HANDLE_VALUE)
		CloseHandle(device);
	seek_device(device, 0);
	ReadFile(device, buf, SECTOR_SIZE, &read, 0);
	_es16_buffer(buf, SECTOR_SIZE);
	// test aes_cbc_192
	memcpy(tmp, buf, SECTOR_SIZE);
	aes_setkey_dec(&cbc_ctx, ata_k1, 192);
	aes_crypt_cbc(&cbc_ctx, AES_DECRYPT, SECTOR_SIZE, iv, tmp, tmp);
	memset(iv, 0, 16);
	ps3_pt = (struct disklabel *)tmp;
    // HDD is Fat
	if(_ES64(ps3_pt->d_magic1) == MAGIC1 && _ES64(ps3_pt->d_magic2) == MAGIC2){
		// get first sector of first region
		u64 start = _ES64(ps3_pt->d_partitions[0].p_start);
		seek_device(device, start * SECTOR_SIZE);
		ReadFile(device, buf, SECTOR_SIZE, &read, 0);
		_es16_buffer(buf, SECTOR_SIZE);
		// decrypt layer_1, ata(aes_cbc_192)
		aes_setkey_dec(&cbc_ctx, ata_k1, 192);
		aes_crypt_cbc(&cbc_ctx, AES_DECRYPT, SECTOR_SIZE, iv, buf, buf);
		memset(iv, 0, 16);
		// decrypt layer_2, vflash(aes-xts-128)
		aes_xts_init(&xts_ctx, AES_DECRYPT, encdec_key1, encdec_key2, 128);
		aes_xts_crypt(&xts_ctx, 8, SECTOR_SIZE, buf, buf);
		ps3_pt = (struct disklabel *)buf;
		// if first region had a partition table, it must be vflash, so its a Fat NOR
		if((_ES64(ps3_pt->d_magic1) == MAGIC1) && (_ES64(ps3_pt->d_magic2) == MAGIC2))
			ps3_type = 2;
		else
		  ps3_type = 1;
		free(ps3_pt);
	  free(tmp);
	  return device;
	}
	// test aes_xts_128
	memcpy(tmp, buf, SECTOR_SIZE);
	aes_xts_init(&xts_ctx, AES_DECRYPT, ata_k1, ata_k2, 128);
	aes_xts_crypt(&xts_ctx, sqnr, SECTOR_SIZE, tmp, tmp);
	ps3_pt = (struct disklabel *)tmp;
	if(_ES64(ps3_pt->d_magic1) == MAGIC1 && _ES64(ps3_pt->d_magic2) == MAGIC2){
		ps3_type = 3;
		free(ps3_pt);
		free(buf);
		return device;
	}
	free(tmp);
	free(buf);
	printf("file \"backup.img\" not found !\n");
	return NULL;
}
/***********************************************************************
* function: get_partitions, get all partitions on a ps3-hdd.
***********************************************************************/
int get_partitions(HANDLE device)
{
	DWORD read = 0;	
	u16 fat_sig;
	u32 fat_info_m1, fat_info_m2, ufs_magic;
	u64 i, k, p_count, start, vflash_m1, vflash_m2;
	struct disklabel *ps3_pt;	
	struct disklabel *vflash_pt;	
	struct fs *ufs2;	
	struct fat_bs *fat;	
	struct fat32_info *fat_info;	
	u8 *buf = malloc(SECTOR_SIZE * 2);	
	u8 *test = malloc(SECTOR_SIZE * 144);	
	u8 *ptr;				
	aes_xts_ctxt_t xts_ctx;	
	aes_xts_ctxt_t xts_ctx_vf;	
	aes_context cbc_ctx;	
	// init decryption context
	switch(ps3_type){																			
		case 1: 
		case 2:
		  aes_setkey_dec(&cbc_ctx, ata_k1, 192);
		  aes_xts_init(&xts_ctx_vf, AES_DECRYPT, encdec_key1, encdec_key2, 128);
		break;
		case 3:
			aes_xts_init(&xts_ctx, AES_DECRYPT, ata_k1, ata_k2, 128);
			aes_xts_init(&xts_ctx_vf, AES_DECRYPT, encdec_key1, encdec_key2, 128);
		break;
	}
	seek_device(device, 0);
	ReadFile(device, buf, SECTOR_SIZE * 2, &read, 0);
	_es16_buffer(buf, SECTOR_SIZE * 2);
	// decrypt hdd partition table
	switch(ps3_type){
		case 1:
		case 2:
			for(i = 0; i < 2; i++){
				aes_crypt_cbc(&cbc_ctx, AES_DECRYPT, SECTOR_SIZE, iv, buf + (SECTOR_SIZE * i), buf + (SECTOR_SIZE * i));
				memset(iv, 0, 16);
			}
		break;
		case 3:
			for(i = 0; i < 2; i++)
				aes_xts_crypt(&xts_ctx, i, SECTOR_SIZE, buf + (SECTOR_SIZE * i), buf + (SECTOR_SIZE * i));
		break;
	}
	ps3_pt = (struct disklabel *)buf;
	// count partitions
	for(p_count = 0; p_count < 8; p_count++){
		if(_ES64(ps3_pt->d_partitions[p_count].p_start) == 0)
		break;
	}
	// for partition count...
	for(i = 0; i < p_count; i++){
		start = _ES64(ps3_pt->d_partitions[i].p_start);
		seek_device(device, start * SECTOR_SIZE);
		ReadFile(device, test, SECTOR_SIZE * 144, &read, 0);
		_es16_buffer(test, SECTOR_SIZE * 144);
		switch(ps3_type){
			case 1:
			case 2:
				for(k = 0; k < 144; k++){
					aes_crypt_cbc(&cbc_ctx, AES_DECRYPT, SECTOR_SIZE, iv, test + (SECTOR_SIZE * k), test + (SECTOR_SIZE * k));
					memset(iv, 0, 16);
				}
			break;
			case 3:
				for(k = 0; k < 144; k++){
					aes_xts_crypt(&xts_ctx, (start + k), SECTOR_SIZE, test + (SECTOR_SIZE * k), test + (SECTOR_SIZE * k));
				}
			break;
		}
		// pointer on buffer test...
		ptr = test;
		fat = (struct fat_bs *)ptr;
		fat_sig = fat->bs_sig;
		ptr += 512;
		fat_info = (struct fat32_info *)ptr;
		fat_info_m1 = fat_info->i_m1;
		fat_info_m2 = fat_info->i_m2;
		ptr += 65024;
		ufs2 = (struct fs *)ptr;
		ufs_magic = _ES32(ufs2->fs_magic);
		if(ufs_magic == 0x19540119){
			hdd0_start = _ES64(ps3_pt->d_partitions[i].p_start);
			hdd0_size  = _ES64(ps3_pt->d_partitions[i].p_size);
			// print hdd0 //
			printf("\nhdd0 Sector/Size:\n");
			printf("-------------------\n");
			printf("[%s] hdd0 Start Sector: 0x%llX\n", __func__, hdd0_start);		
			printf("[%s] hdd0 Size: 0x%llX\n", __func__, hdd0_size*SECTOR_SIZE);	
		}
		if(fat_sig == 0xAA55 && fat_info_m1 == 0x41615252 && fat_info_m2 == 0x61417272){
			hdd1_start = _ES64(ps3_pt->d_partitions[i].p_start);
			hdd1_size	 = _ES64(ps3_pt->d_partitions[i].p_size);
			// print hdd1 //
			printf("\nhdd1 Sector/Size:\n");
			printf("-------------------\n");
			printf("[%s] hdd1 Start Sector: 0x%llX\n", __func__, hdd1_start);		
			printf("[%s] hdd1 Size: 0x%llX\n", __func__, hdd1_size*SECTOR_SIZE);	
		}
		// decrypt buffer test with encdec-keys...
		for(k = 0; k < 144; k++)
			aes_xts_crypt(&xts_ctx_vf, (start + k), SECTOR_SIZE, test + (SECTOR_SIZE * k), test + (SECTOR_SIZE * k));
		vflash_pt = (struct disklabel *)test;
		vflash_m1 = _ES64(vflash_pt->d_magic1);
		vflash_m2 = _ES64(vflash_pt->d_magic2);
		if(vflash_m1 == MAGIC1 && vflash_m2 == MAGIC2){
			vflash_start = _ES64(ps3_pt->d_partitions[i].p_start);
			vflash_size = _ES64(ps3_pt->d_partitions[i].p_size);
			//vflash 2(FAT16) //
			flash_start = _ES64(vflash_pt->d_partitions[1].p_start) + vflash_start;			flash_size = _ES64(vflash_pt->d_partitions[1].p_size);
			// vflash 3(FAT16) //
			flash2_start = _ES64(vflash_pt->d_partitions[2].p_start) + vflash_start;			flash2_size = _ES64(vflash_pt->d_partitions[2].p_size);
			// vflash 4(FAT12) //
			flash3_start = _ES64(vflash_pt->d_partitions[3].p_start) + vflash_start;			flash3_size = _ES64(vflash_pt->d_partitions[3].p_size);
			// print vflash //
			printf("vflash Offset/Size:\n");
			printf("-------------------\n");
			printf("[%s] vflash Start Address: 0x%llX\n", __func__, vflash_start*0x200);		
			printf("[%s] vflash Size: 0x%llX\n", __func__, vflash_size*0x200);	
			printf("[%s] flash Start Address: 0x%llX\n", __func__, flash_start*0x200);		
			printf("[%s] flash Size: 0x%llX\n", __func__, flash_size*0x200);	
			printf("[%s] flash2 Start Address: 0x%llX\n", __func__, flash2_start*0x200);		
			printf("[%s] flash2 Size: %llX\n", __func__, flash2_size*0x200);	
			printf("[%s] flash3 Start Address: 0x%llX\n", __func__, flash3_start*0x200);		
			printf("[%s] flash3 Size: 0x%llX\n", __func__, flash3_size*0x200);	
		}
	}
	return 0;
}
/***********************************************************************
* function: read_device, read decrypted data from ps3-hdd.
* 	HANDLE device		 = device-handle
* 	uint8_t *buf     = puffer//_print_buf(buf, 0, 64); in den gelesen wird
* 	int64_t numbytes = anzahl der zu lesenden bytes
* 	int dev_off			 = byte offset in hdd
***********************************************************************/
s64 read_device(HANDLE device, u8 *buf, u64 numbytes, u64 dev_off)
{
	s64 i, ret, r_sec, r_byte, remain;
	DWORD read;
	u8 tmp1[SECTOR_SIZE];
	u8 *tmp2;
	aes_xts_ctxt_t xts_ctx;
	aes_xts_ctxt_t xts_ctx_vf;
	aes_context cbc_ctx;
	
	u64 seq_nr = dev_off / SECTOR_SIZE;// number of sector to read, sequenz nummer für AES-XTS
	u64 byte_rest = dev_off % SECTOR_SIZE;// byte offset into sector
	u64 sec_rest = SECTOR_SIZE - byte_rest;// rest byte im sector, ab byte offset in sektor... */
	i = ret = r_sec = r_byte = remain = 0;
	
	seek_device(device, seq_nr * SECTOR_SIZE);// seek to start, (file-handle fix)
	
	// set decryption context
	switch(ps3_type){
		case 1:
		case 2:
			aes_setkey_dec(&cbc_ctx, ata_k1, 192);
			aes_xts_init(&xts_ctx_vf, AES_DECRYPT, encdec_key1, encdec_key2, 128);
		break;
		case 3:
			aes_xts_init(&xts_ctx, AES_DECRYPT, ata_k1, ata_k2, 128);
			aes_xts_init(&xts_ctx_vf, AES_DECRYPT, encdec_key1, encdec_key2, 128);
		break;
	}
	
	// check device handle
	if(device == INVALID_HANDLE_VALUE){
		printf("[%s][%d] invalid_handle\n", __func__, __LINE__);
		return -1;
	}
	
	// read and swap whole first sector
	ret = ReadFile(device, tmp1, SECTOR_SIZE, &read, NULL);
	_es16_buffer(tmp1, SECTOR_SIZE);
	
	// decrypt
	switch(ps3_type){
		case 1:
		case 2:
			aes_crypt_cbc(&cbc_ctx, AES_DECRYPT, SECTOR_SIZE, iv, tmp1, tmp1);
			memset(iv, 0, 16);
		break;
		case 3:
			aes_xts_crypt(&xts_ctx, seq_nr, SECTOR_SIZE, tmp1, tmp1);
		break;
	}
	
	// if region vflash
	if(vflash_start != 0)
		if((seq_nr >= vflash_start) && (seq_nr <= vflash_start + vflash_size))
			aes_xts_crypt(&xts_ctx_vf, seq_nr, SECTOR_SIZE, tmp1, tmp1);

	if(numbytes <= sec_rest){/* wenn zu kopierende byte < oder = der zu lesende byte... */
		memcpy(buf, tmp1 + byte_rest, numbytes);/* bytes aus erstem sector in buf kopieren... */
		return numbytes;/* return: gelesene bytes. */
	}
	
	if(numbytes > sec_rest){/* wenn noch mehr kopiert werden muss... */
		memcpy(buf, tmp1 + byte_rest, sec_rest);/* bytes aus erstem sector in buf kopieren... */
		remain = numbytes - sec_rest;/* noch zu kopierende bytes ausrechnen... */
		
		if((remain / SECTOR_SIZE) > 0){/* wenn rest byte >= 512... */
			r_sec = remain / SECTOR_SIZE;/* rest sektoren anzahl ausrechnen... */
		
			tmp2 = malloc(r_sec * SECTOR_SIZE);
			
			ReadFile(device, tmp2, r_sec * SECTOR_SIZE, &read, NULL);/* alle sektoren einlesen... */
			_es16_buffer(tmp2, r_sec * SECTOR_SIZE);/* sektoren byte swap... */
			
			switch(ps3_type){
				case 1:
				case 2:
					for(i = 0; i < r_sec; i++){
						aes_crypt_cbc(&cbc_ctx, AES_DECRYPT, SECTOR_SIZE, iv, tmp2 + (SECTOR_SIZE * i), tmp2 + (SECTOR_SIZE * i));
						memset(iv, 0, 16);
					}
				break;
				case 3:
					for(i = 0; i < r_sec; i++)
						aes_xts_crypt(&xts_ctx, (seq_nr + 1) + i, SECTOR_SIZE, tmp2 + (SECTOR_SIZE * i), tmp2 + (SECTOR_SIZE * i));
				break;
			}
			
			if(vflash_start != 0)
				if(((seq_nr + 1) >= vflash_start) && ((seq_nr + 1) <= vflash_start + vflash_size))
					for(i = 0; i < r_sec; i++)
						aes_xts_crypt(&xts_ctx_vf, (seq_nr + 1) + i, SECTOR_SIZE, tmp2 + (SECTOR_SIZE * i), tmp2 + (SECTOR_SIZE * i));
			
			memcpy(buf + sec_rest, tmp2, r_sec * SECTOR_SIZE);
			free(tmp2);
			
			if((numbytes - sec_rest - (r_sec * SECTOR_SIZE)) > 0){
				r_byte = numbytes - sec_rest - (r_sec * SECTOR_SIZE);
				
				ReadFile(device, tmp1, SECTOR_SIZE, &read, NULL);/* rest byte einlesen... */
				_es16_buffer(tmp1, SECTOR_SIZE);/* sektor byte swap... */
				
				switch(ps3_type){	
					case 1:
					case 2:
						aes_crypt_cbc(&cbc_ctx, AES_DECRYPT, SECTOR_SIZE, iv, tmp1, tmp1);
						memset(iv, 0, 16);
					break;
					case 3:
						aes_xts_crypt(&xts_ctx, (seq_nr + 1 + r_sec), SECTOR_SIZE, tmp1, tmp1);
					break;
				}
				
				if(vflash_start != 0)
					if(((seq_nr + 1 + r_sec) >= vflash_start) && ((seq_nr + 1 + r_sec) <= vflash_start + vflash_size))
						aes_xts_crypt(&xts_ctx_vf, (seq_nr + 1 + r_sec), SECTOR_SIZE, tmp1, tmp1);
				
				memcpy(buf + sec_rest + (r_sec * SECTOR_SIZE), tmp1, r_byte); /* rest byte in buf kopieren */
				
				return numbytes;
			}
			return numbytes;
		}
		
		// remaining bytes smaller than one sector...
		r_byte = numbytes - sec_rest;
		
		ReadFile(device, tmp1, SECTOR_SIZE, &read, NULL);/* rest byte einlesen... */
		_es16_buffer(tmp1, SECTOR_SIZE);/* sektor byte swap... */
		
		switch(ps3_type){/* welche entschlüsselung... */
			case 1:
			case 2:
				aes_crypt_cbc(&cbc_ctx, AES_DECRYPT, SECTOR_SIZE, iv, tmp1, tmp1);
				memset(iv, 0, 16);
			break;
			case 3:
				aes_xts_crypt(&xts_ctx, (seq_nr + 1), SECTOR_SIZE, tmp1, tmp1);
			break;
		}
		
		// if a vflash and data into him
		if(vflash_start != 0)
			if(((seq_nr + 1) >= vflash_start) && ((seq_nr + 1) <= vflash_start + vflash_size))
				aes_xts_crypt(&xts_ctx_vf, (seq_nr + 1), SECTOR_SIZE, tmp1, tmp1);
		
		// copy out rest data
		memcpy(buf + sec_rest, tmp1, r_byte);
		
		return numbytes;
	}
	return 0;
}
/***********************************************************************
* Read decrypted sector/s from ps3 hdd/image.
* 
* ps3_context *ctx = ps3 device information
* uint8_t *buf     = buffer to hold data
* s64 n_sec        = count of sectors to read
* s64 sec_num      = start sector number on hdd
***********************************************************************/
/* s64 block_read(HANDLE device, u8 *buf, s64 n_sec, s64 sec_num)
{
	s64 i;
	DWORD n_read;
	
	// check device handle
	if(device <= 0)
		return -1;

	// read and byte swap data
	seek_device(device, sec_num * SECTOR_SIZE);
	ReadFile(device, buf, n_sec * SECTOR_SIZE, &n_read, 0);
	_es16_buffer(buf, n_sec * SECTOR_SIZE);
	
	// decrypt layer 1(ATA)
	switch(ps3_type) {
		case 1:  // FAT_NAND
		case 2:  // FAT_NOR
			for(i = 0; i < n_sec; i++) {
				aes_crypt_cbc(&cbc_dec, AES_DECRYPT, SECTOR_SIZE, ctx->iv, buf + (SECTOR_SIZE * i), buf + (SECTOR_SIZE * i));
				memset(ctx->iv, 0, 16);
			}
			break;
		case 3:  // SLIM_NOR
			for(i = 0; i < n_sec; i++)
				aes_xts_crypt(&xts_dec, sec_num + i, SECTOR_SIZE, buf + (SECTOR_SIZE * i), buf + (SECTOR_SIZE * i));
			break;
	}
	
	// if data into VFLASH region, decrypt layer 2 too
	if(vflash_start != 0)
		for(i = 0; i < n_sec; i++)
			if(((sec_num + i) >= vflash_start) && ((sec_num + i) <= (vflash_start + vflash_size)))
			  aes_xts_crypt(&xts_dec_vf, sec_num + i, SECTOR_SIZE, buf + (SECTOR_SIZE * i), buf + (SECTOR_SIZE * i));
  
	return (s64)n_read;
} */
/***********************************************************************
* Write encrypted sector/s to ps3 hdd/image.
* 
* ps3_context *ctx = ps3 device information
* uint8_t *buf     = buffer with data to write
* s64 n_sec        = count of sectors to write
* s64 sec_num      = start sector number on hdd
***********************************************************************/
s64 block_write(HANDLE device, u8 *buf, s64 n_sec, s64 sec_num)
{
	s64 i;
	DWORD n_write;
	aes_xts_ctxt_t xts_ctx;
	aes_xts_ctxt_t xts_ctx_vf;
	aes_context cbc_ctx;
  	
	// check device handle
	if(device <= 0)
		return -1;
	
	// if data into VFLASH region, encrypt layer 2(VFLASH) first
	if(vflash_start != 0)
		for(i = 0; i < n_sec; i++)
			if(((sec_num + i) >= vflash_start) && ((sec_num + i) <= (vflash_start + vflash_size)))
			  aes_xts_crypt(&xts_ctx_vf, sec_num + i, SECTOR_SIZE, buf + (SECTOR_SIZE * i), buf + (SECTOR_SIZE * i));
	
	// encrypt layer 1(ATA)
	switch(ps3_type) {
		case 1:  // FAT_NAND
		case 2:  // FAT_NOR
			for(i = 0; i < n_sec; i++) {
				aes_crypt_cbc(&cbc_ctx, AES_ENCRYPT, SECTOR_SIZE, iv, buf + (SECTOR_SIZE * i), buf + (SECTOR_SIZE * i));
				memset(iv, 0, 16);
			}
	    break;
		case 3:  // SLIM_NOR
			for(i = 0; i < n_sec; i++)
				aes_xts_crypt(&xts_ctx, sec_num + i, SECTOR_SIZE, buf + (SECTOR_SIZE * i), buf + (SECTOR_SIZE * i));
		break;
	}
	
	// byte swap data and write to HDD
	_es16_buffer(buf, n_sec * SECTOR_SIZE);
	seek_device(device, sec_num * SECTOR_SIZE);
	WriteFile(device, buf, n_sec * SECTOR_SIZE, &n_write, NULL);
	
	return (s64)n_write;
}
/***********************************************************************
* Write encrypted data to ps3 hdd.
* 
* ps3_context *ctx = ps3 device information
* uint8_t *buf     = buffer with data to encrypt and write
* int64_t numbytes = write size in bytes(must not be sector aligned)
* int64_t dev_off	 = byte offset on hdd(must not be sector aligned)
***********************************************************************/
s64 write_device(HANDLE device, u8 *buf, u64 numbytes, s64 dev_off)
{
	s64 r_sec = 0, r_byte = 0, remain = 0;
	u8 tmp1[SECTOR_SIZE];
	
	u64 seq_nr    = dev_off / SECTOR_SIZE;
	u64 byte_rest = dev_off % SECTOR_SIZE;
	u64 sec_rest  = SECTOR_SIZE - byte_rest;
	
	read_device(device, tmp1, 1, seq_nr);
  
	if(numbytes <= sec_rest) {
		memcpy(tmp1 + byte_rest, buf, numbytes);
		block_write(device, tmp1, 1, seq_nr);
		return numbytes;
	}
  
	if(numbytes > sec_rest) {
		memcpy(tmp1 + byte_rest, buf, sec_rest);
		block_write(device, tmp1, 1, seq_nr);
		
		remain = numbytes - sec_rest;
		
		if((remain / SECTOR_SIZE) > 0) {
			r_sec = remain / SECTOR_SIZE;
			block_write(device, buf + sec_rest, r_sec, seq_nr + 1);
			
			if((numbytes - sec_rest - (r_sec * SECTOR_SIZE)) > 0) {
				r_byte = numbytes - sec_rest - (r_sec * SECTOR_SIZE);
				read_device(device, tmp1, 1, (seq_nr + 1 + r_sec));
				memcpy(tmp1, buf + sec_rest + (r_sec * SECTOR_SIZE), r_byte);
				block_write(device, tmp1, 1, (seq_nr + 1 + r_sec));
				return numbytes;
			}
			return numbytes;
		}
		
		r_byte = numbytes - sec_rest;
		read_device(device, tmp1, 1, (seq_nr + 1));
		memcpy(tmp1, buf + sec_rest, r_byte);
		block_write(device, tmp1, 1, (seq_nr + 1));
		return numbytes;
	}
	
	return 0;
}


/* fat stuff */
/***********************************************************************
* function: init_fat_old, init FAT12/16 file-system.	
***********************************************************************/
struct fat_bs* init_fat_old(HANDLE device, u64 start)
{
	struct fat_bs* fat;
	u8 *buf = malloc(SECTOR_SIZE);
	
	
	seek_device(device, (start * SECTOR_SIZE));
	read_device(device, buf, SECTOR_SIZE, (start * SECTOR_SIZE));
	
	fat = (struct fat_bs *)buf;
	
	return fat;
}
/***********************************************************************
* function: init_fat_old, init FAT12/16 file-system.	
***********************************************************************/
struct fat32_bs* init_fat32(HANDLE device, u64 start)
{
	struct fat32_bs *fat32;
	u8 *buf = malloc(SECTOR_SIZE);
	
	
	seek_device(device, (start * SECTOR_SIZE));
	read_device(device, buf, SECTOR_SIZE, (start * SECTOR_SIZE));
	
	fat32 = (struct fat32_bs *)buf;
	
	return fat32;
}
/***********************************************************************
* Function: get FAT type, bestimmt FAT typ.
* 	struct fat_bs *fat     = bootsektor FAT12/16.
* 	struct fat32_bs *fat32 = bootsektor FAT32.
* 	u8 type                = checke auf 1(FAT12/16) oder 2(FAT32).
* return: int (12, 16, 32)
***********************************************************************/
int get_fat_type(struct fat_bs *fat)
{
	int t1, t2;
	t1 = t2 = 0;
	
	t1 = ((fat->bs_maxroot * 0x20) + (fat->bs_ssize - 1)) / fat->bs_ssize;
	
	if(fat->bs_tsec == 0)
		t2 = (fat->bs_nrsec - fat->bs_rsec - fat->bs_nrfat * fat->bs_fsize - t1) / fat->bs_csize;
	
	if(fat->bs_nrsec == 0)
		t2 = (fat->bs_tsec - fat->bs_rsec - fat->bs_nrfat * fat->bs_fsize - t1) / fat->bs_csize;
	
	if(t2 < 4085)															/* FAT12 */
		return 12; 
	
	if(t2 >= 4085 && t2 < 65525)							/* FAT16 */
		return 16; 
		
	if(t1 == 0 && t2 >= 65525)								/* FAT32 */
		return 32; 
		
	return 0;
}
/***********************************************************************
* function: fat_how_free_bytes, gibt die freien bytes einer FAT partition
* zurück.
***********************************************************************/
u64 fat_how_free_bytes(HANDLE device, u64 storage, struct fat_bs *fat, struct fat32_bs *fat32)
{
	int i = 0, t = 0;
	u64 count = 0, free_byte = 0, data_clu = 0;
	u8 *fat_buf, *buf;
	struct f_entry *add = NULL;
	
	
	if(fat)
		t = get_fat_type(fat);									/* FAT type bestimmen... */
		
	if(fat32)
		t = 32;
	
	switch(t){
		case 12:
			data_clu = ((fat->bs_tsec + fat->bs_nrsec) * fat->bs_ssize - data_off(fat)) / clu_size(fat);/* data cluster in partition */
			buf = malloc(0x02);																																					/* buffer für entry allokieren... */
			fat_buf = malloc(fat_size(fat));																														/* buffer für FAT allokieren... */
			
			seek_device(device, (storage * SECTOR_SIZE) + fat1_off(fat));
			read_device(device, fat_buf, (fat_size(fat)), (storage * SECTOR_SIZE) + fat1_off(fat));
			
			for(i = 2; i < data_clu; i ++){
				memcpy(buf, fat_buf + (fat12_e(fat, i) - fat1_off(fat)), 0x02);
				
				add = (struct f_entry*)buf;
				if((i % 2) == 0){add->entry = add->entry & 0x00000FFF;}	/* entry adresse aufbereiten... */
				else{add->entry = add->entry >> 4 & 0x00000FFF;}
				add->entry &= 0x00000FFF;
					
				if(add->entry == 0x00000000)
					count++;
			}
			
			free_byte = count * clu_size(fat);
			free(add);
			free(fat_buf);
			return free_byte;
		break;
		case 16:
			data_clu = ((fat->bs_tsec + fat->bs_nrsec) * fat->bs_ssize - data_off(fat)) / clu_size(fat);	/* data cluster in partition */
			buf = malloc(0x02);																													/* buffer für entry allokieren... */
			fat_buf = malloc(fat_size(fat));																						/* buffer für FAT allokieren... */
			seek_device(device, (storage * SECTOR_SIZE) + fat1_off(fat));
			read_device(device, fat_buf, fat_size(fat), (storage * SECTOR_SIZE) + fat1_off(fat));
			
			for(i = 0; i < data_clu; i ++){				  																		/* free cluster zählen... */
				memcpy(buf, fat_buf + (i * 2), 0x02);
				
				add = (struct f_entry*)buf;
				add->entry &= 0x0000FFFF;
						
				if(add->entry == 0x00000000)
					count++;
			}
			
			free_byte = count * clu_size(fat);
			
			free(add);
			free(fat_buf);
			return free_byte;
		break;
		case 32:
			data_clu = (fat32->bs_nrsec * fat32->bs_ssize - data_off32(fat32)) / clu_size32(fat32); /* data cluster in partition */
			buf = malloc(0x04);																																			/* buffer für entry allokieren... */
			fat_buf = malloc(fat_size32(fat32));							  																		/* buffer für FAT allokieren... */
			
			seek_device(device, (storage * SECTOR_SIZE) + fat1_off32(fat32));
			read_device(device, fat_buf, (fat_size32(fat32)), (storage * SECTOR_SIZE) + fat1_off32(fat32));
			
			for(i = 0; i < data_clu; i ++){				  																		/* free cluster zählen... */
				memcpy(buf, fat_buf + (i * 4), 0x04);
						
				add = (struct f_entry*)buf;
						
				if(add->entry == 0x00000000)
					count++;
			}
			
			free_byte = count * clu_size32(fat32);
			
			free(add);
			free(fat_buf);
			return free_byte;
		break;
	}
	
	return 0;
}
/***********************************************************************
* Funktion: fat_count_cluster_list, zählt alle cluster einer chain und
* gibt die anzahl zurück.
* 	HANDLE device         = device-handle
* 	u64 storage						= partition
* 	struct fat_bs *fat_fs = struct fat_fs
* 	fat_add_t cluster		  = start cluster desen count wir suchen
***********************************************************************/
fat_clu_list* fat_get_cluster_list(HANDLE device, u64 storage, struct fat_bs *fat_fs, struct fat32_bs *fat32, fat_add_t cluster)
{
	int i, fat_typ;
	u32 count = 0;
	fat_add_t tmp = cluster;
	struct f_entry *add;
	u8 *buf = malloc(0x04);
	u32 *clu_list;
	fat_clu_list *list = NULL;
	
	
	if(fat_fs){
		fat_typ = get_fat_type(fat_fs);															/* FAT typ bestimmen... */
		
		switch(fat_typ){
			case 12:																														/* wenn FAT12... */
				if(cluster == 0){																									/* /wenn cluster 0(ROOT)... */
					count = root_size(fat_fs) / clu_size(fat_fs);
					clu_list = malloc(count * sizeof(*clu_list));
					clu_list = malloc(sizeof(*clu_list));
					list = malloc(sizeof(*list));
					list->clu_add = clu_list;
					list->count = count;
					clu_list[0] = 0;
					return list;
				}
			
				for(i = 0;; i++){																						/* FAT entries zählen... */
					seek_device(device, (storage * SECTOR_SIZE) + fat12_e(fat_fs, tmp));
					read_device(device, buf, 0x02, (storage * SECTOR_SIZE) + fat12_e(fat_fs, tmp));
					
					add = (struct f_entry*)buf;																/* adresse vom buffer in struct f_entry... */
					if((tmp % 2) == 0){add->entry = add->entry & 0x00000FFF;}	/* entry adresse aufbereiten... */
					else{add->entry = add->entry >> 4 & 0x00000FFF;}
					add->entry &= 0x00000FFF;
				
					tmp = add->entry;																					/* nächster cluster... */
					count++;																									/* entry count erhöhen... */
				
					if(add->entry == 0x00000FFE || add->entry == 0x00000FFF)	/* wenn cluster BAD oder EOF, abbrechen... */
						break;
				}
				
				clu_list = malloc(count * sizeof(*clu_list));								/* cluster-liste in größe von entry-count allokieren... */
				list = malloc(sizeof(*list));																/* struct cluster liste allokieren... */
				list->clu_add = clu_list;																		/* beides verbinden... */
				list->count = count;                                				/* cluster count in struct cluster-liste kopieren... */
			
				tmp = cluster;																							/* aktuelle cluster-Nr. in tmp zwischenspeichern... */
					
				for(i = 0; i < count; i++){																	/* alle FAT entries holen... */
					clu_list[i] = tmp;																				/* pointer i auf liste anfang... */
					
					seek_device(device, (storage * SECTOR_SIZE) + fat12_e(fat_fs, tmp));
					read_device(device, buf, 0x02, (storage * SECTOR_SIZE) + fat12_e(fat_fs, tmp));
					
					if((tmp % 2) == 0){add->entry = add->entry & 0x00000FFF;}	/* entry adresse aufbereiten... */
					else{add->entry = add->entry >> 4 & 0x00000FFF;}
					
					add = (struct f_entry*)buf;																/* adresse vom buffer in struct f_entry... */	
					tmp = add->entry;																					/* nächster cluster... */
					
					if(add->entry == 0x00000FFE || add->entry == 0x00000FFF)	/* wenn cluster BAD oder EOF, abbrechen... */
						break;
				}	
			break;
			case 16:																											/* wenn FAT16... */
				if(cluster == 0){																									/* wenn cluster 0(ROOT)... */
					count = root_size(fat_fs) / clu_size(fat_fs);
					clu_list = malloc(count * sizeof(*clu_list));
					clu_list = malloc(sizeof(*clu_list));
					list = malloc(sizeof(*list));
					list->clu_add = clu_list;
					list->count = count;
					clu_list[0] = 0;
					return list;
				}
				
				for(i = 0;; i++){																						/* FAT entries zählen... */
					seek_device(device, (storage * SECTOR_SIZE) + fat16_e(fat_fs, tmp));
					read_device(device, buf, 0x02, (storage * SECTOR_SIZE) + fat16_e(fat_fs, tmp));	

					add = ((struct f_entry*)buf);															/* adresse vom buffer in struct f_entry... */
					add->entry &= 0x0000FFFF;																	/* adresse maskieren... */
					tmp = add->entry;																					/* nächster cluster... */
					
					count++;																									/* entry count erhöhen... */
					
					if(add->entry == 0x0000FFFE || add->entry == 0x0000FFFF)	/* wenn cluster BAD oder EOF, abbrechen... */
						break;
				}
			
				clu_list = malloc(count * sizeof(*clu_list));								/* cluster-liste in größe von entry-count allokieren... */
				list = malloc(sizeof(*list));																/* struct cluster liste allokieren... */
				list->clu_add = clu_list;																		/* beides verbinden... */
				list->count = count;                                				/* cluster count in struct cluster-liste kopieren... */
			
				tmp = cluster;																							/* aktuelle cluster-Nr. in tmp zwischenspeichern... */
				
				for(i = 0; i < count; i++){																	/* alle FAT entries holen... */
					clu_list[i] = tmp;																				/* pointer i auf liste anfang... */
					
					seek_device(device, (storage * SECTOR_SIZE) + fat16_e(fat_fs, tmp));
					read_device(device, buf, 0x02, (storage * SECTOR_SIZE) + fat16_e(fat_fs, tmp));
					
					add = (struct f_entry*)buf;																/* adresse vom buffer in struct f_entry... */
					tmp = add->entry;																					/* nächster cluster... */
				
					if(add->entry == 0x0000FFFE || add->entry == 0x0000FFFF)	/* wenn cluster BAD oder EOF, abbrechen... */
					break;
				}
			break;
		}	
	
	return list;
	}
	else{ /* FAT32... */
		
		if(cluster == 0){																									/* wenn cluster 0(ROOT)... */
			cluster = 2;
		}
		
		for(i = 0;; i++){																						/* FAT entries zählen... */
			seek_device(device, (storage * SECTOR_SIZE) + fat32_e(fat32, tmp));
			read_device(device, buf, 0x04, (storage * SECTOR_SIZE) + fat32_e(fat32, tmp));
			
			add = ((struct f_entry*)buf);															/* adresse vom buffer in struct f_entry... */
			tmp = add->entry;																					/* nächster cluster... */
			count++;																									/* entry count erhöhen... */
					
			if(add->entry == 0x0FFFFFFE || add->entry == 0x0FFFFFFF)	/* wenn cluster BAD oder EOF, abbrechen... */
				break;
		}
		
		clu_list = malloc(count * sizeof(*clu_list));								/* cluster-liste in größe von entry-count allokieren... */
		list = malloc(sizeof(*list));																/* struct cluster liste allokieren... */
		list->clu_add = clu_list;																		/* beides verbinden... */
		list->count = count;                                				/* cluster count in struct cluster-liste kopieren... */
			
		tmp = cluster;																							/* aktuelle cluster-Nr. in tmp zwischenspeichern... */
		
		for(i = 0; i < count; i++){																	/* alle FAT entries holen... */
			clu_list[i] = tmp;																				/* pointer i auf liste anfang... */
			
			seek_device(device, (storage * SECTOR_SIZE) + fat32_e(fat32, tmp));
			read_device(device, buf, 0x04, (storage * SECTOR_SIZE) + fat32_e(fat32, tmp));
			
			add = (struct f_entry*)buf;																/* adresse vom buffer in struct f_entry... */
			tmp = add->entry;																					/* nächster cluster... */
				
			if(add->entry == 0x0FFFFFFE || add->entry == 0x0FFFFFFF)	/* wenn cluster BAD oder EOF, abbrechen... */
			break;
		}
		
		return list;
	}
}
/***********************************************************************
*Funktion zum freigeben einer cluster-liste.
***********************************************************************/
void fat_free_cluster_list(fat_clu_list *list)
{
	free(list->clu_add);
	free(list);
}
/***********************************************************************
* Funktion: fat_read_cluster, zählt alle cluster einer chain und
* gibt die anzahl zurück.
* 	HANDLE device         = device-handle
* 	u64 storage						= partition
* 	struct fat_bs *fat_fs = struct fat_fs
* 	fat_clu_list *list		= adress-liste der einzulesenden cluster
* 	u8 *buf               = pointer auf puffer für einzulesende cluster
* 	u32 start             = start cluster adresse
* 	u32 count             = cluster anzahl
* return: anzahl der gelesenen cluster.
***********************************************************************/
int fat_read_cluster(HANDLE device, u64 storage, struct fat_bs *fat_fs, struct fat32_bs *fat32, fat_clu_list *list, u8 *buf, u32 start, u32 count)
{
	int i;
	
	
	if(fat_fs){
		/* if cluster list... */
		if(list){
			if(list->clu_add[0] == 0){ /* if first add in list 0, read in root-dir-data in size of root-size... */
				for(i = 0; i < list->count; i++){
					seek_device(device, (storage * SECTOR_SIZE) + root_off(fat_fs));
					read_device(device, buf + (i * clu_size(fat_fs)), clu_size(fat_fs), (storage * SECTOR_SIZE) + root_off(fat_fs) + (i * clu_size(fat_fs)));
				}
				return i;
			}
			
			if(list->clu_add[0] >= 2){ /* reguläre cluster(ab 2), beginnen in data area... */
				for(i = 0; i < list->count; i++){
					seek_device(device, (storage * SECTOR_SIZE) + clu_off(fat_fs, list->clu_add[i]));
					read_device(device, buf + (i * clu_size(fat_fs)), clu_size(fat_fs), (storage * SECTOR_SIZE) + clu_off(fat_fs, list->clu_add[i]));
				}
				return i;	
			}
		}
		
		/* wenn keine liste, vom start in anzahl von count lesen... */
		for(i = 0; i < count; i++){
			seek_device(device, (storage * SECTOR_SIZE) + clu_off(fat_fs, start));
			read_device(device, buf + (i * clu_size(fat_fs)), clu_size(fat_fs), (storage * SECTOR_SIZE) + clu_off(fat_fs, start));
		}
		return i;
	}
	else{ /* FAT32 */
		/* wenn es eine cluster liste gibt... */
		if(list){
			if(list->clu_add[0] >= 2){ /* reguläre cluster(ab 2), beginnen in data area... */
				for(i = 0; i < list->count; i++){
					seek_device(device, (storage * SECTOR_SIZE) + clu_off32(fat32, list->clu_add[i]));
					read_device(device, buf + (i * clu_size32(fat32)), clu_size32(fat32), (storage * SECTOR_SIZE) + clu_off32(fat32, list->clu_add[i]));
				}
				return i;	
			}
		}
		
		/* wenn keine liste, von start in anzahl von count lesen... */
		for(i = 0; i < count; i++){
			seek_device(device, (storage * SECTOR_SIZE) + clu_off32(fat32, start));
			read_device(device, buf + (i * clu_size32(fat32)), clu_size32(fat32), (storage * SECTOR_SIZE) + clu_off32(fat32, start));
		}
		
		return i;
	}
}
/***********************************************************************
* Funktion: get_fat_entry_count, bestimmt die anzahl an entries in einem
* directory.
* 	u8 *clusters = puffer mit entry daten.
* return: entry anzahl
***********************************************************************/
int fat_get_entry_count(u8 *clusters)
{
	int i;
	u8 c, cs1, cs2, seq;
	u8 *p = clusters;
	u8 *tmp = malloc(0x20);
	struct sfn_e *sfn;
	
	c = cs1 = cs2 = seq = 0;
	
	
	while(*p != 0x00){   																	/* while entries exist... */
		if(*p != 0xE5){																			/* if entry not deleted... */
			p += 0x0B;				 																/* pointer on entry attributes... */
			
			if(*p == 0x0F){																		/* if entry LFN... */
				p += 0x02;																			/* pointer on entry checksume... */
				cs1 = *p;																				/* get checksume... */
				p -= 0x0D;																			/* pointer back on entry start... */
				seq = *p & 0x1F;															  /* get ordinal number... */
			
				for(i = 0; i < seq; i++){												/* for each LFN... */
					p += 0x0D;																		/* pointer on entry checksume... */
				
					if(*p == cs1){																/* if checksume right...  */
						p -= 0x0D;																	/* pointer back on entry start... */
						p += 0x20;																	/* pointer on next entry... */
					}
				}
				memcpy(tmp, p, 0x20);														/* SFN in buffer tmp... */
				sfn = (struct sfn_e*)tmp;
			
				for (i = 0; i < 11; i++) {											/* calc checksume of SFN... */
					cs2 = ((cs2 & 0x01) ? 0x80 : 0) + (cs2 >> 1);
					cs2 = cs2 + sfn->d_name[i];
				}
			
				if(cs2 == cs1){																	/* if checksume right, entry ok... */
					c++;																	        /* entry count + 1... */
				}
				cs2 = 0;
			}
			else{																							/* entry is solo SFN... */
				p -= 0x0B;																			/* pointer back on entry start... */
				c++;																		    		/* entry count + 1... */
			}
			p += 0x20;																				/* pointer on next entry... */
		}
		else{
			p += 0x20;																				/* pointer on next entry... */
		}
	}
	
	return c;																							/* return entry count... */
}
/***********************************************************************
* get LFN entrie name
***********************************************************************/
int get_lfn_name(u8 *tmp, char part[M_LFN_LENGTH])
{
	int i;
	
	
	part[0]  = tmp[0x01];
	part[1]  = tmp[0x03];
	part[2]  = tmp[0x05];
	part[3]  = tmp[0x07];
	part[4]  = tmp[0x09];
	part[5]  = tmp[0x0E];
	part[6]  = tmp[0x10];
	part[7]  = tmp[0x12];
	part[8]  = tmp[0x14];
	part[9]  = tmp[0x16];
	part[10] = tmp[0x18];
	part[11] = tmp[0x1C];
	part[12] = tmp[0x1E];
	
	for(i = 0; i < M_LFN_LENGTH; i++)
		if(part[i] == 0xFF) 
			part[i] = 0x20;
	
	return 0;
}
/***********************************************************************
* sfn name aufbereiten
***********************************************************************/
int get_sfn_name(u8 *sfn_name, u8 *name)
{
	int i;
	u8 tmp_nam[9] = {0x20};											/* puffer für name-part */
	u8 tmp_ext[4] = {0x20};										  /* puffer für extension-part */
	
	for(i = 0; i < 260; i++)										/* reset name string... */
				name[i] = 0x00;
	
	
	memcpy(tmp_nam, sfn_name, 8); 							/* name-part kopieren... */
	for(i = 0; i < 9; i++)       								/* nach string ende suchen... */
		if(tmp_nam[i] == 0x20) 										/* wenn space... */
			tmp_nam[i] = 0x00;											/* mit nullterminator ersetzen... */
	
	if(sfn_name[8] == 0x20){										/* gibt es keine extension, name ist dir-name... */
		memcpy(name, tmp_nam, strlen((const char*)tmp_nam));		/* dir-name kopieren... */
		return 0;
	}
	else{																				/* wenn es eine extension gibt, name ist file-name... */
		memcpy(tmp_ext, sfn_name + 8, 3); 				/* extension kopieren... */
		sprintf((char*)name, "%s.%s", tmp_nam, tmp_ext); /* file-name zusammensetzen... */
		return 0;
	}
	
	return -1;
}
/***********************************************************************
* Funktion: fat_get_entry_list, erstellt eine puffer mit allen entries
* plus daten.
* 	u8 *cluster = fat-cluster/s mit entry daten.
* 	u8 *name    = entry name der gesucht wird.
***********************************************************************/
int fat_dir_search_entry(u8 *cluster, u8 *s_name, u8 *tmp)
{
	int i, x, y;
	u16 n_len;
	u8 *e_ptr = cluster;
	u8 cs_1, cs_2, seq;
	char part[M_LFN_LENGTH] = {0};
	char lfname[M_LFN_ENTRIES][M_LFN_LENGTH];
	char name[260];
	struct sfn_e *sfn;
	
	cs_1 = cs_2 = seq = n_len = 0;
	for(x = 0; x < M_LFN_ENTRIES; x++)
		for(y = 0; y < M_LFN_LENGTH; y++)
			lfname[x][y] = 0x00;
	
	
	/* search entries... */
	e_ptr = cluster;
	while(*e_ptr != 0x00){   																	/* while entries exist... */
		if(*e_ptr != 0xE5){																			/* if entry not deleted... */
			e_ptr += 0x0B;				 																/* pointer on entry attributes... */
		
		if(*e_ptr == 0x0F){																			/* if entry LFN... */
			e_ptr += 0x02;																				/* pointer on entry checksume... */
			cs_2 = *e_ptr;																				/* get checksume... */
			e_ptr -= 0x0D;																				/* pointer on entry start... */
			seq = *e_ptr & 0x1F;																	/* get ordinal number... */
			
			for(i = 0; i < seq; i++){															/* for each LFN... */
				memcpy(tmp, e_ptr, 0x20);														/* copy entry in puffer... */
				
				if(tmp[0x0D] == cs_2){															/* if checksume right... */
					get_lfn_name(tmp, part);
					strncpy(lfname[seq - 1 - i], part, 13);
					e_ptr += 0x20;
				}
			}
			
			memcpy(tmp, e_ptr, 0x20);															/* SFN in puffer... */
			sfn = (struct sfn_e*)tmp;
			
			for (i = 0; i < 11; i++) {														/* checksume des SFN berechnen... */
				cs_1 = ((cs_1 & 0x01) ? 0x80 : 0) + (cs_1 >> 1);
				cs_1 = cs_1 + sfn->d_name[i];
			}

			if(cs_1 == cs_2){																			/* if checksume right, entry ok... */
				cs_1 = 0;																						/* checksume reset... */
				memcpy(name, lfname, 260);													/* copy name from name array... */
				
				for(x = 0; x < M_LFN_ENTRIES; x++)									/* lfname array reset... */
					for(y = 0; y < M_LFN_LENGTH; y++)
						lfname[x][y] = 0x00;
				
				if(strcmp(name, (const char *)s_name) == 0){   			/* check name... */
					return sfn->d_start_clu;
				}
				/* wenn der name nicht s_name ist... */
			}
			/* wenn checksume nicht richtig... */
		}
		else if(*e_ptr != 0x0F){																/* wenn ein single SFN, ohne LFN... */
			e_ptr -= 0x0B;
			memcpy(tmp, e_ptr, 0x20);														 	/* copy entry in puffer... */
			sfn = (struct sfn_e*)tmp;
			get_sfn_name(sfn->d_name, (u8*)name);									/* SFN-name erstellen... */
			
			if(strcmp(name, (const char *)s_name) == 0){   				/* check name... */
				return sfn->d_start_clu;
			}
			/* wenn der name nicht s_name ist... */
		}
			e_ptr += 0x20;																				/* pointer on next entry... */
		}	/* wenn entry deleted... */
		else{
			e_ptr += 0x20;																				/* pointer on next entry... */
		}
		
	}
	return -1;
}
/***********************************************************************
* Funktion: fat_lookup_path, gibt cluster-adresse eines files oder dirs
* 					zurück, oder 0 wenn file/dir nicht existiert.
* 	HANDLE device         = device-handle
* 	u64 storage						= partition
* 	struct fat_bs *fat_fs = struct fat_fs
* 	u8 *path 		    	    = gesuchter pfad
* 	fat_add_t fat_root    = root-verzeichniss, ab diesem verzeichniss
* 													soll gesucht werden. wenn 0, wird vom ROOT
* 													des fs ausgegangen.
***********************************************************************/
struct sfn_e* fat_lookup_path(HANDLE device, u64 storage, struct fat_bs *fat_fs, struct fat32_bs *fat32, u8 *path, fat_add_t fat_root)
{
	int ret;
	u8 *str, *n_str, *clu_data=0;
	fat_add_t cluster=0;
	fat_add_t tmp_clu = 0;																			/* temp cluster adressen kopie, für suche */
	fat_clu_list *list;																					/* cluster liste für dir-data */
	struct sfn_e *entry;
	u8 *s_entry = malloc(0x20);
	
	
	str = malloc(MAX_PATH);																			/* string(str) in größe von MAX_PATH allokieren */
	
	if(fat_fs){
		if(path[0] == '/'){																					/* wenn pfad mit / beginnt... */
			memcpy(str, &path[1], strlen((char*)path));								/* pfad ohne / in str kopieren... */
			cluster = 0;																							/* suche in root beginnen... */
		}

	/* pfade in seine elemente zerlegen und für jedes element... */
	for(n_str = str; n_str && n_str[0]; n_str = str){
		if((str = memchr(str, 0x2F, strlen((char*)str)))){
			*str = '\0';
			str++;
		}

		tmp_clu = cluster;

		list = fat_get_cluster_list(device, storage, fat_fs, 0, tmp_clu);			/* cluster count und adressen listen holen... */
		clu_data = malloc(list->count * clu_size(fat_fs));										/* speicher für cluster data allokieren... */
		fat_read_cluster(device, storage, fat_fs, 0, list, clu_data, 0, 0);		/* cluster in puffer lesen... */
		fat_free_cluster_list(list);																					/* cluster liste freigeben... */
			
		ret = fat_dir_search_entry(clu_data, n_str, s_entry);
			
		if(ret != -1){															  												/* wenn element existiert... */
			cluster = ret;															  											/* found cluster... */
		}
		else{																						    				  				/* wenn element nicht existiert... */
			free(clu_data);
			return NULL;
		}	
	}
	
	
	entry = (struct sfn_e*)s_entry;																					/* ziel-entry einlesen und zurückgeben... */
	
	free(clu_data);
	return entry;
	}
	else{ /* FAT32 */
	
		if(path[0] == '/'){																					/* wenn pfad mit / beginnt... */
			memcpy(str, &path[1], strlen((char*)path));								/* pfad ohne / in str kopieren... */
			cluster = 2;																							/* suche in root beginnen... */
		}

		/* pfad in seine elemente zerlegen und für jedes element... */
		for(n_str = str; n_str && n_str[0]; n_str = str){
			if((str = memchr(str, 0x2F, strlen((char*)str)))){
				*str = '\0';
				str++;
			}
			
			tmp_clu = cluster;

			list = fat_get_cluster_list(device, storage, 0, fat32, tmp_clu);			/* cluster count und adressen listen holen... */
			clu_data = malloc(list->count * clu_size32(fat32));										/* speicher für cluster data allokieren... */
			fat_read_cluster(device, storage, 0, fat32, list, clu_data, 0, 0);		/* cluster in puffer lesen... */
			fat_free_cluster_list(list);																					/* cluster liste freigeben... */
			
			ret = fat_dir_search_entry(clu_data, n_str, s_entry);
			
			
			if(ret != -1){															  												/* wenn element existiert... */
				cluster = ret;
			}
			else{																						    				  				/* wenn element nicht existiert... */
				free(clu_data);
				return NULL;
			}
		}
		
		entry = (struct sfn_e*)s_entry;																					/* ziel-entry einlesen und zurückgeben... */
		
		if(entry->d_start_clu == 0)
			entry->d_start_clu = 2;
		
		free(str);
		free(clu_data);
		return entry;
	}
}
/***********************************************************************
* Funktion: fat_get_entries, erstellt eine puffer mit metadaten aller
* entries.
* 	u8 *in  									 = puffer mit roh entry daten.
* 	struct fat_dir_entry *dirs = struct array für entries.
***********************************************************************/
int fat_get_entries(u8 *buf, struct fat_dir_entry *dirs)
{
	int i, k, l, m;
	u8 cs_1, cs_2, sq;
	u8 *e_ptr = buf;
	u8 *tmp = malloc(0x20);
	char lfname[M_LFN_ENTRIES][M_LFN_LENGTH];
	char part[M_LFN_LENGTH] = {0};
	char name[260];
	struct sfn_e *sfn;
	
	e_ptr = buf;
	
	cs_1 = cs_2 = sq = m = 0;
	for(k = 0; k < M_LFN_ENTRIES; k++)
		for(l = 0; l < M_LFN_LENGTH; l++)
			lfname[k][l] = 0x00;
	
	
	/* process entries... */
	while(*e_ptr != 0x00){   																	/* while entries exist... */
		if(*e_ptr != 0xE5){																			/* if entry not deleted... */
			e_ptr += 0x0B;				 																/* pointer on entry-attribute... */
			
			if(*e_ptr == 0x0F){																		/* if entry LFN... */
				e_ptr += 0x02;																			/* pointer on entry-checksume... */
				cs_2 = *e_ptr;																			/* get checksume... */
				e_ptr -= 0x0D;																			/* pointer on entry start... */
				sq = *e_ptr & 0x1F;																	/* get ordinal number... */
			
				for(i = 0; i < sq; i++){														/* for each found LFN... */
					memcpy(tmp, e_ptr, 0x20);													/* copy entry in puffer... */
				
					if(tmp[0x0D] == cs_2){														/* if checksume right... */
						get_lfn_name(tmp, part);												/* read LFN... */
						strncpy(lfname[sq - 1 - i], part, 13);
						e_ptr += 0x20;
					}
				}
				
				memcpy(tmp, e_ptr, 0x20);														/* SFN in puffer... */
				sfn = (struct sfn_e*)tmp;
				
				for (i = 0; i < 11; i++) {													/* calc checksume for SFN... */
					cs_1 = ((cs_1 & 0x01) ? 0x80 : 0) + (cs_1 >> 1);
					cs_1 = cs_1 + sfn->d_name[i];
				}
				
				if(cs_1 == cs_2){																		/* if checksume right, entry ok... */
					cs_1 = 0;																					/* checksume reset... */
					memcpy(name, lfname, 260);												/* copy name from name array... */
					
					for(k = 0; k < M_LFN_ENTRIES; k++)								/* lfname array reset... */
						for(l = 0; l < M_LFN_LENGTH; l++)
							lfname[k][l] = 0x00;
					
					memcpy(dirs[m].fd_dos_name, sfn->d_name, 11);
					dirs[m].fd_att 			 = sfn->d_att;
					dirs[m].fd_case 		 = sfn->d_case;
					dirs[m].fd_ctime_ms  = sfn->d_ctime_ms;
					dirs[m].fd_ctime 		 = sfn->d_ctime;
					dirs[m].fd_cdate 		 = sfn->d_cdate;
					dirs[m].fd_atime 		 = sfn->d_atime;
					dirs[m].fd_adate 	   = sfn->d_adate;
					dirs[m].fd_mtime 	   = sfn->d_mtime;
					dirs[m].fd_mdate 	   = sfn->d_mdate;
					dirs[m].fd_start_clu = sfn->d_start_clu;
					dirs[m].fd_size      = sfn->d_size;
					memcpy(dirs[m].fd_name, name, 261);
					m++;
				}
			}
			else{
				e_ptr -= 0x0B;
				memcpy(tmp, e_ptr, 0x20);														/* copy entry in puffer... */
				sfn = (struct sfn_e*)tmp;														/* SFN-entry in struct laden... */
				memset(name, 0x00, 260);														/* string name reseten... */
				get_sfn_name(sfn->d_name, (u8*)name);								/* SFN-name erstellen... */
				
				memcpy(dirs[m].fd_dos_name, sfn->d_name, 11);
				dirs[m].fd_att 			 = sfn->d_att;
				dirs[m].fd_case 		 = sfn->d_case;
				dirs[m].fd_ctime_ms  = sfn->d_ctime_ms;
				dirs[m].fd_ctime 		 = sfn->d_ctime;
				dirs[m].fd_cdate 		 = sfn->d_cdate;
				dirs[m].fd_atime 		 = sfn->d_atime;
				dirs[m].fd_adate 	   = sfn->d_adate;
				dirs[m].fd_mtime 	   = sfn->d_mtime;
				dirs[m].fd_mdate 	   = sfn->d_mdate;
				dirs[m].fd_start_clu = sfn->d_start_clu;
				dirs[m].fd_size      = sfn->d_size;
				memcpy(dirs[m].fd_name, name, 261);
				m++;
			}
			e_ptr += 0x20;																				/* pointer on next entry... */
		}
		else{
			e_ptr += 0x20;																				/* pointer on next entry... */
		}
	}
	
	return 0;
}
/***********************************************************************
*sortier function für directory entries
***********************************************************************/
int sort_dir(const void *first, const void *second)
{
	const struct fat_dir_entry *a = first;
	const struct fat_dir_entry *b = second;
	
	
	if(!strcmp((const char *)a->fd_name, ".")){
		return -1;
	}
	else if(!strcmp((const char *)b->fd_name, ".")){
		return 1;
	}
	else if(!strcmp((const char *)a->fd_name, "..")){
		return -1;
	}
	else if(!strcmp((const char *)b->fd_name, "..")){
		return 1;
	}
	else{
		return strcmp((const char *)a->fd_name, (const char *)b->fd_name);
	}
}
/***********************************************************************
*date time
***********************************************************************/
struct date_time fat_datetime_from_entry(u16 date, u16 time)
{
	struct date_time t;
	u8 day, month, year, hour, minutes, seconds;
	day = month = year = hour = minutes = seconds = 0;
	
	
	day     = (date & 0x001F) >>  0;
	month   = (date & 0x01E0) >>  5;
	year    = (date & 0xFE00) >>  9;
	hour    = (time & 0xF800) >> 11;
	minutes = (time & 0x07E0) >>  5;
	seconds = (time & 0x001F) <<  1;
	
	t.day = day;	
	t.month = month;	 
	t.year = year;	
	t.hour = hour;	
	t.minutes = minutes;	
	t.seconds = seconds;
	
	return t;
}
/***********************************************************************
* Funktion: fat_print_dir_list, listet die entries eines dir auf.
* 	HANDLE device         = device-handle
* 	u64 storage						= partitions start sektor
* 	struct fat_bs *fat_fs = struct fat_fs
* 	u8 *path 		    	    = pfad zum directory
* 	u8 *volume						= partition
***********************************************************************/
int fat_print_dir_list(HANDLE device, u64 storage, struct fat_bs *fat_fs, struct fat32_bs *fat32, u8 *path, u8 *volume, u64 free_byte)
{	
	int i, entry_count;
	u8 *buffer;
	u64 file_count, dir_count, byte_use, byte_free;
	struct sfn_e *dir;
	fat_clu_list *list;
	struct fat_dir_entry *dirs;
	struct date_time dt;
	char timestr[64];
	char sizestr[32];
	char byte_use_str[32];
	char byte_free_str[32];
	file_count = dir_count = byte_use = byte_free = 0;
	
	
	if(fat_fs){
		if((strlen((char*)path)) == 1 && path[0] == 0x2F){
			list = fat_get_cluster_list(device, storage, fat_fs, 0, 0);				/* cluster liste für ROOT erstellen... */
			buffer = malloc(list->count * clu_size(fat_fs));									/* puffer für cluster allokieren... */
			fat_read_cluster(device, storage, fat_fs, 0, list, buffer, 0, 0);	/* cluster in puffer kopieren... */
			fat_free_cluster_list(list);																			/* cluster liste freigeben... */
			entry_count = fat_get_entry_count(buffer);												/* dir-entry anzahl bestimmen... */
			dirs = malloc(entry_count * sizeof(*dirs));												/* fat_dir_entry array in anzahl der entries allokieren... */
			fat_get_entries(buffer, dirs);																		/* entries in dirs struct-array kopieren... */
			
		}
		else{
			/* pfad überprüfen, existent oder nicht... */
			if((dir = fat_lookup_path(device, storage, fat_fs, 0, path, 0)) == NULL){
				printf("no such file or directory!\n");
				return -1;
			}
		
			/* wenn pfad zu keinem directory führt... */
			if((dir->d_att & A_DIR) != A_DIR){
				printf("can't show, not a directory!\n");
				return -1;
			}
		
			list = fat_get_cluster_list(device, storage, fat_fs, 0, dir->d_start_clu);	
			buffer = malloc(list->count * clu_size(fat_fs));	
			fat_read_cluster(device, storage, fat_fs, 0, list, buffer, 0, 0);	
			fat_free_cluster_list(list);	
			entry_count = fat_get_entry_count(buffer);	
			dirs = malloc(entry_count * sizeof(*dirs));	
			fat_get_entries(buffer, dirs);	
		}
	}
	else{
		if((strlen((char*)path)) == 1 && path[0] == 0x2F){
			list = fat_get_cluster_list(device, storage, 0, fat32, fat32->bs32_rootclu);	
			buffer = malloc(list->count * clu_size32(fat32));	
			fat_read_cluster(device, storage, 0, fat32, list, buffer, 0, 0);	
			fat_free_cluster_list(list);	
			entry_count = fat_get_entry_count(buffer);	
			dirs = malloc(entry_count * sizeof(*dirs));	
			fat_get_entries(buffer, dirs);	
		}
		else{
			/* pfad überprüfen, existent oder nicht... */
			if((dir = fat_lookup_path(device, storage, 0, fat32, path, 0)) == NULL){
				printf("no such file or directory!\n");
				return -1;
			}
		
			/* wenn pfad zu keinem directory führt... */
			if((dir->d_att & A_DIR) != A_DIR){
				printf("can't show, not a directory!\n");
				return -1;
			}
			
			list = fat_get_cluster_list(device, storage, 0, fat32, dir->d_start_clu);
			buffer = malloc(list->count * clu_size32(fat32));
			fat_read_cluster(device, storage, 0, fat32, list, buffer, 0, 0);
			fat_free_cluster_list(list);
			entry_count = fat_get_entry_count(buffer);
			dirs = malloc(entry_count * sizeof(*dirs));
			fat_get_entries(buffer, dirs);
		}
	}
	
	free(buffer);																										/* buffer freigeben... */
	
	qsort(dirs, entry_count, sizeof(*dirs), sort_dir); 							/* entries sortieren... */
	
	/* dir entries ausgeben... */
	printf("\n Volume is ps3_hdd %s\n", volume);
	printf(" Directory of %s/%s\n\n", volume, path);
	
	for(i = 0; i < entry_count; ++i){																					/* für jeden entry... */
		dt = fat_datetime_from_entry(dirs[i].fd_mdate, dirs[i].fd_mtime);   		/* date und time formatieren... */
		sprintf(timestr, "%02d.%02d.%04d  %02d:%02d",														/* time-string erstellen... */
				dt.month, dt.day, dt.year + 1980, dt.hour, dt.minutes);
		
		if((dirs[i].fd_att & A_DIR) == A_DIR){																	/* wenn entry ein dir... */
			dir_count++;
			sprintf(sizestr, "<DIR>");																						/* sizestr gleich <DIR>... */
			printf("%s    %-14s %s\n", timestr, sizestr, dirs[i].fd_name);
		}
		else{
			file_count++;
			byte_use = byte_use + dirs[i].fd_size;
			print_commas(dirs[i].fd_size, sizestr);
			printf("%s    %14s %s\n", timestr, sizestr, dirs[i].fd_name);					/* alle entries(file) ausgeben... */
		}	
	}
	print_commas(byte_use, byte_use_str);
	print_commas(free_byte, byte_free_str);
	printf("%16llu File(s),  ", file_count);
	printf("%s bytes\n", byte_use_str);
	printf("%16llu Dir(s),  ", dir_count);
	printf("%s bytes free\n", byte_free_str);
	
	free(dirs);
	return 0;
}
/***********************************************************************
* Funktion: fat_copy_data, kopiert files/folders ins programmverzeichnis.
* 	HANDLE device          = device-handle
* 	u64 storage						 = partitions start sektor
* 	struct fat_bs *fat_fs  = struct fat_fs, wenn FAT12/16
* 	struct fat32_bs *fat32 = struct fat32_bs, wenn FAT32
* 	u8 *srcpath 		    	 = quelle
* 	u8 *destpath					 = ziel
***********************************************************************/
int fat_copy_data(HANDLE device, u64 storage, struct fat_bs *fat_fs, struct fat32_bs *fat32, char *srcpath, char *destpath)
{
	int i, entry_count;
	u8 *buf=0;
	char *tmp;
	s64 totalsize, readsize, read;
	char string[MAX_PATH];
	char newdest[MAX_PATH];
	int using_con;
	struct sfn_e *dir = NULL;	
	fat_clu_list *list = NULL;
	struct fat_dir_entry *dirs;
	struct utimbuf filetime;
	FILE *out;
	
	
	if(strlen(srcpath) == 1 && srcpath[0] == 0x2F)
		return 0;
	
	using_con = (destpath && (!Stricmp((const char *)destpath, "CON") || !(Strnicmp((const char *)destpath, "CON.", 4))));
	
	/* quell-pfad überprüfen, existent oder nicht... */
	if(fat_fs){
		if((dir = fat_lookup_path(device, storage, fat_fs, 0, (u8*)srcpath, 0)) == NULL){
			printf("can't copy, no such file or directory!\n");
			return -1;
		}
	}
	else if(fat32){
		if((dir = fat_lookup_path(device, storage, 0, fat32, (u8*)srcpath, 0)) == NULL){
			printf("can't copy, no such file or directory!\n");
			return -1;
		}
	}
	
	if(destpath == NULL){														/* wenn kein zielpfad angegeben wurde...*/
		char *base = basename((const char *)srcpath);
		strcpy(newdest, "./");												/* ziel = programm ordner... */
		strcat(newdest, base);
		free(base);
	}
	else{	
		while(destpath[strlen((const char *)destpath) - 1] == '/')
			destpath[strlen((const char *)destpath) - 1] = '\0';
	
		strcpy(newdest, (const char *)destpath);
	}
	
	totalsize = dir->d_size;
	
	if((dir->d_att & A_DIR) == A_DIR){
		char *dirdest;
		char nextsrc[256] = {0x00};
		char nextdest[MAX_PATH] = {0x00};
		struct stat sb;
		
		if(using_con){
			return -1;
		}
		
		if(!stat(newdest, &sb)){
			if((sb.st_mode & S_IFMT) != S_IFDIR){
				return -1;
			}
			dirdest = strdup(newdest);
		}
		else{
			// if(mkdir(newdest, 0777) == -1){
			if(mkdir(newdest) == -1){
				dirdest = valid_filename(newdest, 0);
				// if(mkdir(dirdest,0777) == -1){
				if(mkdir(dirdest) == -1){
					free(dirdest);
					return -1;
				}
			}
			else{
				dirdest = strdup(newdest);
			}
		}
		
		/* entries in diesem ordner verarbeiten... */
		if(fat_fs){
			list = fat_get_cluster_list(device, storage, fat_fs, 0, dir->d_start_clu);	/* cluster anzahl + adressen holen... */
			buf = malloc(list->count * clu_size(fat_fs));																/* puffer für cluster(s) allokieren... */
			fat_read_cluster(device, storage, fat_fs, 0, list, buf, 0, 0);							/* cluster(s) in puffer kopieren... */
		}
		else if(fat32){
			list = fat_get_cluster_list(device, storage, 0, fat32, dir->d_start_clu);	  /* cluster anzahl + adressen holen... */
			buf = malloc(list->count * clu_size32(fat32));															/* puffer für cluster(s) allokieren... */
			fat_read_cluster(device, storage, 0, fat32, list, buf, 0, 0);								/* cluster(s) in puffer kopieren... */
		}
		
		fat_free_cluster_list(list);																									/* cluster liste freigeben... */
		entry_count = fat_get_entry_count(buf);																				/* dir-entry anzahl bestimmen... */
		dirs = malloc(entry_count * sizeof(*dirs));																		/* dir_entry array in anzahl der entries allokieren... */
		fat_get_entries(buf, dirs);																										/* entries in dirs struct-array kopieren... */
		free(buf);
		
		/* für jeden entry... */
		for(i = 0; i < entry_count; ++i){
			if(!strcmp((const char *)dirs[i].fd_name, ".") || !strcmp((const char *)dirs[i].fd_name, ".."))		/* pseudo ordner auslassen... */
				continue;
			
			/* pfad zu entry erstellen und mit dieser funktion verarbeiten... */
			strcpy(nextsrc, (const char *)srcpath);
			
			if(srcpath[strlen((const char *)srcpath) - 1] != '/')
				strcat(nextsrc, "/");
				
			strcat(nextsrc, (const char *)dirs[i].fd_name);
			strcpy(nextdest, dirdest);
			strcat(nextdest, "/");
			strcat(nextdest, (const char *)dirs[i].fd_name);
			sprintf(string, "%s/%s", srcpath, dirs[i].fd_name);
			printf("copy -> %s\n", string);
			
			if(fat_fs){
				fat_copy_data(device, storage, fat_fs, 0, nextsrc, nextdest);
			}
			else if(fat32){
				fat_copy_data(device, storage, 0, fat32, nextsrc, nextdest);
			}
		}
		free(dirs);
		return 0;
	}
	
	readsize = 0;
	read = 0;
	
	tmp = valid_filename(newdest, using_con);
	
	strcpy(newdest, (const char *)tmp);
	free(tmp);
	
	out = fopen(newdest, "wb");															/* zieldatei erstellen... */
	if(!out){																								/* wenn nicht möglich... */						
		printf("can't create file! \"%s\"\n", newdest);				/* fehlermeldung... */
		return -1;
	}
	
	if(fat_fs){
		buf = malloc(clu_size(fat_fs));																							/* buffer in cluster size... */
		list = fat_get_cluster_list(device, storage, fat_fs, 0, dir->d_start_clu);	/* cluster anzahl + adressen holen... */
	
		for(i = 0; readsize < totalsize; i++){																			/* file daten kopieren... */
			if(totalsize - readsize < clu_size(fat_fs)){
				seek_device(device, (storage * SECTOR_SIZE) + clu_off(fat_fs, list->clu_add[i]));
				read = read_device(device, buf, totalsize - readsize, (storage * SECTOR_SIZE) + clu_off(fat_fs, list->clu_add[i]));
				fwrite(buf, 1, read, out);
				readsize += read;
			}
			else{
				seek_device(device, (storage * SECTOR_SIZE) + clu_off(fat_fs, list->clu_add[i]));
				read = read_device(device, buf, clu_size(fat_fs), (storage * SECTOR_SIZE) + clu_off(fat_fs, list->clu_add[i]));
				fwrite(buf, 1, read, out);
				readsize += read;
			}
			
			fprintf(stderr,"(%03lld%%)\r", readsize * 100 / totalsize);
		}
	}
	else if(fat32){
		buf = malloc(clu_size32(fat32));	
		list = fat_get_cluster_list(device, storage, 0, fat32, dir->d_start_clu);	
	
		for(i = 0; readsize < totalsize; i++){	
			if(totalsize - readsize < clu_size32(fat32)){
				seek_device(device, (storage * SECTOR_SIZE) + clu_off32(fat32, list->clu_add[i]));
				read = read_device(device, buf, totalsize - readsize, (storage * SECTOR_SIZE) + clu_off32(fat32, list->clu_add[i]));
				fwrite(buf, 1, read, out);
				readsize += read;
			}
			else{
				seek_device(device, (storage * SECTOR_SIZE) + clu_off32(fat32, list->clu_add[i]));
				read = read_device(device, buf, clu_size32(fat32), (storage * SECTOR_SIZE) + clu_off32(fat32, list->clu_add[i]));
				fwrite(buf, 1, read, out);
				readsize += read;
			}

			fprintf(stderr,"(%03lld%%)\r", readsize * 100 / totalsize);
		}
	}
	
	fat_free_cluster_list(list);	             														/* cluster liste freigeben... */
	free(buf);						
	fclose(out);
	
	filetime.actime = fat2unix_time(dir->d_atime, dir->d_adate);					/* setze last access time... */
	filetime.modtime = fat2unix_time(dir->d_mtime, dir->d_mdate);					/* setze last modified time... */
	utime(newdest, &filetime);																						/* setze erstell zeit, jetzt... */
	
	return 0;
}


/* UFS2 */
/***********************************************************************
* init ufs2
***********************************************************************/
struct fs* ufs2_init(HANDLE device)
{ 
	struct fs *fs;
	u8 *buf = malloc(SBLOCKSIZE);
	
	seek_device(device, (hdd0_start + 128) * SECTOR_SIZE);
	read_device(device, buf, SBLOCKSIZE, (hdd0_start + 128) * SECTOR_SIZE);
	
	fs = (struct fs*)buf;
	
	/* endian fix */
	fs->fs_sblkno						= _ES32(fs->fs_sblkno);
	fs->fs_cblkno						= _ES32(fs->fs_cblkno);
	fs->fs_iblkno						= _ES32(fs->fs_iblkno);
	fs->fs_dblkno						= _ES32(fs->fs_dblkno);
	fs->fs_ncg							= _ES32(fs->fs_ncg);
	fs->fs_bsize						= _ES32(fs->fs_bsize);
	fs->fs_fsize						= _ES32(fs->fs_fsize);
	fs->fs_frag							= _ES32(fs->fs_frag);
	fs->fs_minfree					= _ES32(fs->fs_minfree);
	fs->fs_bmask						= _ES32(fs->fs_bmask);
	fs->fs_fmask						= _ES32(fs->fs_fmask);
	fs->fs_bshift						= _ES32(fs->fs_bshift);
	fs->fs_fshift						= _ES32(fs->fs_fshift);
	fs->fs_maxcontig				= _ES32(fs->fs_maxcontig);
	fs->fs_maxbpg						= _ES32(fs->fs_maxbpg);
	fs->fs_fragshift				= _ES32(fs->fs_fragshift);
	fs->fs_fsbtodb					= _ES32(fs->fs_fsbtodb);
	fs->fs_sbsize						= _ES32(fs->fs_sbsize);
	fs->fs_nindir						= _ES32(fs->fs_nindir);
	fs->fs_inopb						= _ES32(fs->fs_inopb);
	fs->fs_old_nspf					= _ES32(fs->fs_old_nspf);
	fs->fs_cssize						= _ES32(fs->fs_cssize);
	fs->fs_cgsize						= _ES32(fs->fs_cgsize);
	fs->fs_spare2						= _ES32(fs->fs_spare2);
	fs->fs_ipg							= _ES32(fs->fs_ipg);
	fs->fs_fpg							= _ES32(fs->fs_fpg);
	fs->fs_pendingblocks		= _ES64(fs->fs_pendingblocks);
	fs->fs_pendinginodes		= _ES32(fs->fs_pendinginodes);
	fs->fs_avgfilesize			= _ES32(fs->fs_avgfilesize);
	fs->fs_avgfpdir					= _ES32(fs->fs_avgfpdir);
	fs->fs_save_cgsize			= _ES32(fs->fs_save_cgsize);
	fs->fs_flags						= _ES32(fs->fs_flags);
	fs->fs_contigsumsize		= _ES32(fs->fs_contigsumsize);
	fs->fs_maxsymlinklen		= _ES32(fs->fs_maxsymlinklen);
	fs->fs_old_inodefmt			= _ES32(fs->fs_old_inodefmt);
	fs->fs_maxfilesize			= _ES64(fs->fs_maxfilesize);
	fs->fs_qbmask						= _ES64(fs->fs_qbmask);
	fs->fs_qfmask						= _ES64(fs->fs_qfmask);
	fs->fs_state						= _ES32(fs->fs_state);
	fs->fs_old_postblformat = _ES32(fs->fs_old_postblformat);
	fs->fs_old_nrpos				= _ES32(fs->fs_old_nrpos);
	fs->fs_magic						= _ES32(fs->fs_magic);
	
	return fs;
}
/***********************************************************************
*Funktion: read_direntry, liest einen directory-entry ein
* 	void *buf 						= pointer auf puffer mit dir-entrie daten
* 	struct direct* direct = pointer auf struct für dir-entries
* return:
* 	dir->d_reclen         = länge des verarbeiteten record's aus buf
***********************************************************************/
int ufs_read_direntry(void *buf, struct direct* dir)
{
	memcpy(dir, buf, 8);																		/* kopiert die ersten 8 byte in struct dir(d_ino, d_reclen, d_type, d_namlen) */
	strncpy(dir->d_name, &((char*)buf)[8], dir->d_namlen);	/* kopiert, ab byte 9 im puffer, in länge von dir->d_namlen */
	dir->d_name[dir->d_namlen] = '\0';											/* setzt nullterminator an ende des namens */
	return _ES16(dir->d_reclen);														/* gibt record länge zurück */
}
/***********************************************************************
*Funktion zum freigeben einer blockliste.
***********************************************************************/
void ufs_free_block_list(ufs2_block_list *list)
{
	free(list->blk_add);
	free(list);
}
/***********************************************************************
*sortier function für directory entries
* 
***********************************************************************/
int ufs_sort_dir(const void *first, const void *second)
{
	const struct direct *a = first;
	const struct direct *b = second;

	if(!strcmp(a->d_name, ".")){
		return -1;
	}else if(!strcmp(b->d_name, ".")){
		return 1;
	}else if(!strcmp(a->d_name, "..")){
		return -1;
	}else if(!strcmp(b->d_name, "..")){
		return 1;
	}else{
		return strcmp(a->d_name, b->d_name);
	}
}
/***********************************************************************
*Funktion zum einlesen von datenblöcken in einen puffer, basierend auf
*einer blockliste.
* 	HANDLE device								= device-handle
* 	struct fs *fs								= superblock des filesystems
* 	struct ufs2_dinode *di			= 
* 	ufs2_block_list *block_list	= blocklist
* 	u8 *buf											= buffer zum befüllen
* 	ufs_inop start_block				= 
* 	ufs_inop num_blocks					= 
***********************************************************************/
int ufs_read_data(HANDLE device, struct fs *ufs2, struct ufs2_dinode *di, ufs2_block_list *block_list, u8 *buf, ufs_inop start_block, ufs_inop num_blocks)
{
	int i, bsize;
	s64 total, read, len, offset;
	s64 *bl;
	
	bl = block_list->blk_add;

	if(!num_blocks){
		len = _ES64(di->di_size);
		// len = (di->di_size);
	}
	else{
		len = num_blocks * ufs2->fs_fsize;
	}
	
	if(_ES64(di->di_blocks) == 0){
	// if((di->di_blocks) == 0){
		memcpy(buf, di->di_db, _ES64(di->di_size));
		return _ES64(di->di_size);
	}

	total  = 0;
	offset = 0;
	
	for(i = 0; total < start_block * ufs2->fs_fsize; ++i){
		bsize = sblksize(ufs2, _ES64(di->di_size), i);
		// bsize = sblksize(ufs2, (di->di_size), i);

		if(total + bsize > start_block * ufs2->fs_fsize){
			offset = start_block * ufs2->fs_fsize - total;
			break;
		}
		total += bsize;    
	}
	
	for(total = 0; total < len; ++i){
		if(bl[i] != 0 && seek_device(device, (bl[i] * ufs2->fs_fsize) + (hdd0_start * SECTOR_SIZE) + (offset * SECTOR_SIZE)) <= 0)
			return -1;
		
		read = sblksize(ufs2, _ES64(di->di_size), i) - offset;
		// read = sblksize(ufs2, (di->di_size), i) - offset;
		
		offset = 0;
		
		if(read + total > len)
			read = len - total;
		
		if(bl[i] == 0){
			memset(buf, 0, read);
		}
		else if(read_device(device, buf, read, ((bl[i] * ufs2->fs_fsize) + (hdd0_start * SECTOR_SIZE) + offset)) < 0){
			return -1;
		}

		total += read;
		buf += read;
	}

	return total;
}
/***********************************************************************
*Funktion: 
* 	HANDLE device     = device-handle
* 	struct fs *fs     = superblock, struct fs
* 	ufs_inop root_ino = 
* 	ufs_inop ino      = 
***********************************************************************/
ufs_inop ufs_follow_symlinks(HANDLE device, struct fs* ufs2, ufs_inop root_ino, ufs_inop ino)
{
	struct ufs2_dinode dino;
	ufs2_block_list *block_list;
	
	read_inode(device, ufs2, ino, &dino);
	
	// while((_ES16(dino.di_mode) & IFMT) == IFLNK){								/* solange links... */
	while(((dino.di_mode) & IFMT) == IFLNK){								/* solange links... */
		u8 tmpname[MAX_PATH];
		block_list = get_block_list(device, ufs2, &dino);
		ufs_read_data(device, ufs2, &dino, block_list, tmpname, 0, 0);
		ufs_free_block_list(block_list);
		tmpname[_ES64(dino.di_size)] = '\0';
		// tmpname[(dino.di_size)] = '\0';
		ino = ufs_lookup_path(device, ufs2, tmpname, 0, root_ino);
		read_inode(device, ufs2, ino, &dino);
	}

	return ino;																									/* return echten ordner... */
}
/***********************************************************************
*Funktion vom typ ufs2_block_list, zum erstellen der blockliste für
*einen inode.
* 	HANDLE device						= device-handle
* 	struct fs *fs						= superblock des filesystems
* 	struct ufs2_dinode *di	= pointer auf struct des inodes von dem
* 														blocklist erstellt werden soll
* return: ufs2_block_list*
***********************************************************************/
ufs2_block_list* get_block_list(HANDLE device, struct fs *ufs2, struct ufs2_dinode *di)
{ 
	int i, j, k;
	s64 count, totalsize;
	s64 *block_list;
	ufs2_block_list *list;
	s64 *bufx;
	s64 *bufy;
	s64 *bufz;
	
	
	
	/* speicher für block_list einträge allokieren... */
	block_list = malloc(((_ES64(di->di_size) / ufs2->fs_bsize) + 1) * sizeof(*block_list));
	// block_list = malloc((((di->di_size) / ufs2->fs_bsize) + 1) * sizeof(*block_list));
	list = malloc(sizeof(*list));
	list->blk_add = block_list;
	
	count = 0;
	totalsize = 0;
	
	/* direct blocks einlesen... */
	for(i = 0; i < NDADDR; ++i){
		block_list[count] = _ES64(di->di_db[i]);
		totalsize += sblksize(ufs2, _ES64(di->di_size), count);
		// block_list[count] = (di->di_db[i]);
		// totalsize += sblksize(ufs2, (di->di_size), count);
		++count;

		if(totalsize >= _ES64(di->di_size)){
		// if(totalsize >= (di->di_size)){
			return list;
		}	
	}
	
	/* indirect blocks einlesen... */
	bufx = malloc(ufs2->fs_bsize);
	seek_device(device, (hdd0_start * SECTOR_SIZE) + (_ES64(di->di_ib[0]) * ufs2->fs_fsize));
	read_device(device, (u8*)bufx, ufs2->fs_bsize, (hdd0_start * SECTOR_SIZE) + (_ES64(di->di_ib[0]) * ufs2->fs_fsize));
	// seek_device(device, (hdd0_start * SECTOR_SIZE) + ((di->di_ib[0]) * ufs2->fs_fsize));
	// read_device(device, (u8*)bufx, ufs2->fs_bsize, (hdd0_start * SECTOR_SIZE) + ((di->di_ib[0]) * ufs2->fs_fsize));
	
	for(i = 0; i * sizeof(bufx[0]) < ufs2->fs_bsize; ++i){
		block_list[count] = _ES64(bufx[i]);
		totalsize += sblksize(ufs2, _ES64(di->di_size), count);
		// block_list[count] = (bufx[i]);
		// totalsize += sblksize(ufs2, (di->di_size), count);
		++count;
		if(totalsize >= _ES64(di->di_size)){
		// if(totalsize >= (di->di_size)){
			free(bufx);
			return list;
		}
	}
	
	/* double indirect block einlesen... */
	bufy = malloc(ufs2->fs_bsize);
	seek_device(device, (hdd0_start * SECTOR_SIZE) + (_ES64(di->di_ib[1]) * ufs2->fs_fsize));
	read_device(device, (u8*)bufy, ufs2->fs_bsize, (hdd0_start * SECTOR_SIZE) + (_ES64(di->di_ib[1]) * ufs2->fs_fsize));
	// seek_device(device, (hdd0_start * SECTOR_SIZE) + ((di->di_ib[1]) * ufs2->fs_fsize));
	// read_device(device, (u8*)bufy, ufs2->fs_bsize, (hdd0_start * SECTOR_SIZE) + ((di->di_ib[1]) * ufs2->fs_fsize));
	
	for(j = 0; j * sizeof(bufy[0]) < ufs2->fs_bsize; ++j) {
		seek_device(device, (hdd0_start * SECTOR_SIZE) + (_ES64(bufy[j]) * ufs2->fs_fsize));
		read_device(device, (u8*)bufx, ufs2->fs_bsize, (hdd0_start * SECTOR_SIZE) + (_ES64(bufy[j]) * ufs2->fs_fsize));
		// seek_device(device, (hdd0_start * SECTOR_SIZE) + ((bufy[j]) * ufs2->fs_fsize));
		// read_device(device, (u8*)bufx, ufs2->fs_bsize, (hdd0_start * SECTOR_SIZE) + ((bufy[j]) * ufs2->fs_fsize));
		
		for(i = 0; i * sizeof(bufx[0]) < ufs2->fs_bsize; ++i){
			block_list[count] = _ES64(bufx[i]);
			totalsize += sblksize(ufs2, _ES64(di->di_size), count);
			// block_list[count] = (bufx[i]);
			// totalsize += sblksize(ufs2, (di->di_size), count);
			++count;
			
			if(totalsize >= _ES64(di->di_size)){
			// if(totalsize >= (di->di_size)){
				free(bufx);
				free(bufy);
				return list;
			}
		}
	}

	/* triple indirect blocks einlesen... */
	bufz = malloc(ufs2->fs_bsize);
	seek_device(device, (hdd0_start * SECTOR_SIZE) + (_ES64(di->di_ib[2]) * ufs2->fs_fsize));
	read_device(device, (u8*)bufz, ufs2->fs_bsize, (hdd0_start * SECTOR_SIZE) + (_ES64(di->di_ib[2]) * ufs2->fs_fsize));
	// seek_device(device, (hdd0_start * SECTOR_SIZE) + ((di->di_ib[2]) * ufs2->fs_fsize));
	// read_device(device, (u8*)bufz, ufs2->fs_bsize, (hdd0_start * SECTOR_SIZE) + ((di->di_ib[2]) * ufs2->fs_fsize));

	for(k = 0; k * sizeof(bufz[0]) < ufs2->fs_bsize; ++k){
		seek_device(device, (hdd0_start * SECTOR_SIZE) + (_ES64(bufz[k]) * ufs2->fs_fsize));
		read_device(device, (u8*)bufy, ufs2->fs_bsize, (hdd0_start * SECTOR_SIZE) + (_ES64(bufz[k]) * ufs2->fs_fsize));
		// seek_device(device, (hdd0_start * SECTOR_SIZE) + ((bufz[k]) * ufs2->fs_fsize));
		// read_device(device, (u8*)bufy, ufs2->fs_bsize, (hdd0_start * SECTOR_SIZE) + ((bufz[k]) * ufs2->fs_fsize));

		for(j = 0; j * sizeof(bufy[0]) < ufs2->fs_bsize; ++j){
			seek_device(device, (hdd0_start * SECTOR_SIZE) + (_ES64(bufz[j]) * ufs2->fs_fsize));
			read_device(device, (u8*)bufx, ufs2->fs_bsize, (hdd0_start * SECTOR_SIZE) + (_ES64(bufz[j]) * ufs2->fs_fsize));
			// seek_device(device, (hdd0_start * SECTOR_SIZE) + ((bufz[j]) * ufs2->fs_fsize));
			// read_device(device, (u8*)bufx, ufs2->fs_bsize, (hdd0_start * SECTOR_SIZE) + ((bufz[j]) * ufs2->fs_fsize));

			for(i = 0; i * sizeof(bufx[0]) < ufs2->fs_bsize; ++i){
				block_list[count] = _ES64(bufx[i]);
				totalsize += sblksize(ufs2, _ES64(di->di_size), count);
				// block_list[count] = (bufx[i]);
				// totalsize += sblksize(ufs2, (di->di_size), count);
				++count;

				if (totalsize >= _ES64(di->di_size)) {
				// if (totalsize >= (di->di_size)) {
					free(bufx);
					free(bufy);
					free(bufz);
					return list;
				}
			}
		}
	}

	free(bufx);
	free(bufy);
	free(bufz);
	return list;
}
/***********************************************************************
*Funktion zum einlesen eines inode in eine ufs2_dinode struct.
*		HANDLE device					 = device-handle
* 	struct fs *fs  				 = superblock des filesystems
* 	ufs_inop ino					 = zu lesender inode
* 	struct ufs2_dinode *di = pointer auf zu fühlende struct
***********************************************************************/
int read_inode(HANDLE device, struct fs *ufs2, ufs_inop ino, struct ufs2_dinode *di)
{
	s64 byte_offset;																/* inode start offset */
	s64 cg_nmb = ino / ufs2->fs_ipg;								/* cylinder_gruppe des inode bestimmen */
	u8 *buf = malloc(sizeof(struct ufs2_dinode));		/* puffer für inode */
	
	/* inode offset berechnen... */
	byte_offset = (hdd0_start * SECTOR_SIZE) +														/* bytes von partition start bis filesystem start */
							(ufs2->fs_iblkno * ufs2->fs_fsize) +											/* bytes von filesystem start bis start erste inode-table */
							(cg_nmb * (ufs2->fs_fpg * ufs2->fs_fsize)) +  		  			/* bytes bis cg in welcher der inode ist */
							((ino % ufs2->fs_ipg) * sizeof(struct ufs2_dinode));			/* bytes von inode-table start bis gesuchten inode */
	
	
	seek_device(device, byte_offset);																			/* seek zu inode offset... */
	read_device(device, buf, sizeof(struct ufs2_dinode), byte_offset);		/* lese inode in buffer... */
	
	memcpy((u8*)di, buf, sizeof(*di));																		/* inode in struct dinode kopieren... */
	
	
	return 0;
}
/***********************************************************************
*Funktion: 
* 	HANDLE device     = device-handle
* 	struct fs *fs     = superblock
* 	u8 *path 		    	= pfad der verfolgt werden soll
* 	int follow        = 
* 	ufs_inop root_ino = 
***********************************************************************/
ufs_inop ufs_lookup_path(HANDLE device, struct fs* ufs2, u8* path, int follow, ufs_inop root_ino)
{ 
	int ret, i; 
	u8 *s, *sorig, *nexts, *nexte;
	u8 *tmp;
	struct ufs2_dinode dino;
	struct direct dir;
	ufs2_block_list *block_list;
	s64 found_ino = 0;
	
	s = malloc(MAX_PATH);
	sorig = s;
	
	if(path[0] == '/'){																				/* wenn pfad mit / beginnt... */
		memcpy(s, &path[1], strlen((char*)path));								/* pfad ohne / in s kopieren... */
		root_ino = ROOTINO;																			/* und root_inode ist ROOTINO(2) */
	}
	else{																											/* wenn pfad nicht mit / beginnt... */
		memcpy(s, path, strlen((char*)path));										/* ganzen pfad in s kopieren. */
	}
	
	for(nexts = s; nexts && nexts[0]; nexts = s){							/* für alle elemente des pfades... */
		if((s = memchr(s, 0x2F, strlen((char*)s)))){						
			*s = '\0';
			s++;
		}
		
		read_inode(device, ufs2, root_ino, &dino);									/* aktuellen inode einlesen... */
		block_list = get_block_list(device, ufs2, &dino);						/* blockliste für inode daten erstellen... */
		tmp = malloc(_ES64(dino.di_size));													/* speicher für inode daten allokieren... */
		ufs_read_data(device, ufs2, &dino, block_list, tmp, 0, 0);	/* daten anhand von blockliste in puffer tmp einlesen... */
		ufs_free_block_list(block_list);														/* blockliste freigeben... */
		
		nexte = tmp;																								/* tmp in nexte kopieren... */
		
		for(i = 0;; ++i){																						/* für alle entries in den inode daten... */
			ret = ufs_read_direntry(nexte, &dir);											/* lese dir entry... */
			
			if(nexte - tmp >= _ES64(dino.di_size)){										/* wenn alle entries gelesen wurden... */
				free(tmp);
				return 0;
			}

			if(!strcmp(dir.d_name, (const char*)nexts)){							/* wenn name des entry der gesuchter name ist... */
				found_ino = _ES32(dir.d_ino);														/* found_ino gleich ino des gefundenen entry... */
				break;																									/* break... weil fertig */
			}
			nexte += ret;																							/* wenn nicht, nächsten entry im puffer testen... */
		}
		free(tmp);																						    	/* tmp freigeben... */
	
		if(!found_ino)																					  	/* wenn kein ino gefunden wurde... */
			return 0;
	
		if(follow || (s && s[0] != '\0')){													/* wenn symlink... */
			root_ino = ufs_follow_symlinks(device, ufs2, root_ino, found_ino); /* link bis ende folgen... */
		}
		else{
			root_ino = found_ino;
		}
	}
	
	free(sorig);
	return root_ino;
}
/***********************************************************************
*Funktion: print_dir_list, gibt einen verzeichnis inhalt aus.
* 	HANDLE device = device-handle
* 	struct fs *fs = struct fs
* 	u8 *path		  = pfad zum zu lesenden verzeichnis
***********************************************************************/
int ufs_print_dir_list(HANDLE device, struct fs* ufs2, u8* path, u8* volume)
{
	int i, ret, entry_count;	
	u8 *buffer, *tmp;		
	u64 file_count, dir_count, byte_use, byte_free;
	ufs_inop inode;	
	struct ufs2_dinode *root_inode;	
	root_inode = malloc(sizeof(struct ufs2_dinode));	
	ufs2_block_list *block_list;	
	struct direct direntry_tmp;	
	struct direct *dirs;	
	struct ufs2_dinode dinode_tmp;	
	struct tm *tm;	
	char timestr[64];	
	char sizestr[32];	
	char byte_use_str[32];
	char byte_free_str[32];
	char symlinkstr[280];		
	file_count = dir_count = byte_use = byte_free = 0;
	
	
	inode = ufs_lookup_path(device, ufs2, path, 1, ROOTINO);        /* get inode for path... */
	
	if(!inode){																											/* if no inode, path not exist... */
		printf("no such file or directory!\n");
		return -1;
	}
	
	read_inode(device, ufs2, inode, root_inode);                    /* if inode... */
	
	if (!(root_inode->di_mode & IFDIR)) {														/* if inode file... */
		printf("can't show, not a directory!\n");
		return -1;
	}
	
	/* get dir data... */
	block_list = get_block_list(device, ufs2, root_inode);
	buffer = malloc(_ES64(root_inode->di_size) + sizeof(struct direct));
	ufs_read_data(device, ufs2, root_inode, block_list, buffer, 0, 0);
	ufs_free_block_list(block_list);
	
	tmp = buffer;
	
	/* count dir entries... */
	for(entry_count = 0; tmp - buffer < _ES64(root_inode->di_size); ++entry_count){
		ret = ufs_read_direntry(tmp, &direntry_tmp);
		tmp += ret;
	}
	
	dirs = malloc(entry_count * sizeof(*dirs));
	
	tmp = buffer;
	
	for(i = 0; i < entry_count; ++i){
		ret = ufs_read_direntry(tmp, &dirs[i]);
		tmp += ret;
	}
	
	free(buffer);
	
	qsort(dirs, entry_count, sizeof(*dirs), ufs_sort_dir);
	
	/* print dir entries... */
	printf("\n Volume is ps3_hdd %s\n", volume);
	printf(" Directory of %s/%s\n\n", volume, path);
	
	for(i = 0; i < entry_count; ++i){
		read_inode(device, ufs2, _ES32(dirs[i].d_ino), &dinode_tmp);
		
		dinode_tmp.di_mtime = _ES64(dinode_tmp.di_mtime);
		dinode_tmp.di_mode = _ES16(dinode_tmp.di_mode);
		
		tm = localtime((const time_t*) (&dinode_tmp.di_mtime));
		strftime(timestr, 64, "%m.%d.%Y  %H:%M", tm);
		
		if ((dinode_tmp.di_mode & IFMT) == IFLNK){
			u8 tmpname[MAX_PATH];

			block_list = get_block_list(device, ufs2, &dinode_tmp);
			ufs_read_data(device, ufs2, &dinode_tmp, block_list, tmpname, 0, 0);
			ufs_free_block_list(block_list);
			tmpname[dinode_tmp.di_size] = '\0';

			sprintf(symlinkstr, " -> %s", tmpname);
		}
		else{
			symlinkstr[0] = '\0';
		}
		
		if((dinode_tmp.di_mode & IFMT) == IFDIR){
			dir_count++;
			sprintf(sizestr, "<DIR>");
			printf("%s    %-14s %s\n", timestr, sizestr, dirs[i].d_name);
		}
		else{
			file_count++;
			byte_use += _ES64(dinode_tmp.di_size);
			print_commas(_ES64(dinode_tmp.di_size), sizestr);
			printf("%s    %14s %s %s\n", timestr, sizestr, dirs[i].d_name, symlinkstr);
		}
	}
	
	print_commas(byte_use, byte_use_str);
	print_commas(_ES64(ufs2->fs_cstotal.cs_nbfree) * ufs2->fs_bsize, byte_free_str);
	printf("%16llu File(s),  ", file_count);
	printf("%s bytes\n", byte_use_str);
	printf("%16llu Dir(s),  ", dir_count);
	printf("%s bytes free\n", byte_free_str);
	
	
	free(dirs);
	return 0;
}
/***********************************************************************
*Funktion: read_file
* 	HANDLE device     = 
* 	struct fs *fs     = struct fs
* 	ufs_inop root_ino = root
* 	ufs_inop ino      = 
* 	char *srcpath     = 
* 	char *destpath    = 
***********************************************************************/
int ufs_copy_data(HANDLE device, struct fs *ufs2, ufs_inop root_ino, ufs_inop ino, char *srcpath, char *destpath)
{
	int i;
	const char *dir_ = "..";
	s64 totalsize, readsize, read;
	ufs2_block_list *block_list;
	char *buf, *dir, *tmp;
	char newdest[MAX_PATH];
	int using_con;
	FILE *out;
	struct ufs2_dinode dinode;
	struct utimbuf filetime;
	ufs_inop symlink_ino;
	s64 *bl;
	char string[MAX_PATH];
	
	
	if(strlen(srcpath) == 1 && srcpath[0] == 0x2F)
		return 0;
	
	using_con = (destpath && (!Stricmp(destpath, "CON") || !(Strnicmp(destpath, "CON.", 4))));
	
	if(!root_ino || !ino){
		printf("can't copy, no such file or directory!\n");
		return -1;
	}
	
	read_inode(device, ufs2, ino, &dinode);
	
	if((_ES16(dinode.di_mode) & IFMT) == IFLNK){  													/* if symlink... */
		ino = ufs_lookup_path(device, ufs2, (u8*)srcpath, 1, ROOTINO);
		dir = dirname(srcpath);
		symlink_ino = ufs_lookup_path(device, ufs2, (u8*)dir, 1, ROOTINO);

		for(;; symlink_ino = ufs_lookup_path(device, ufs2, (u8*)dir_, 0, symlink_ino)){
			if(symlink_ino == ino){
				printf("\"%s\" is a recursive symlink loop\n", srcpath);
				free(dir);
				return -1;
			}

			if(symlink_ino == ROOTINO)
				break;
		}
		free(dir);
	}
	
	if(destpath == NULL){
		char *base = basename(srcpath);
		strcpy(newdest, "./");
		strcat(newdest, base);
		free(base);
	}
	else{	
		while(destpath[strlen(destpath) - 1] == '/')
			destpath[strlen(destpath) - 1] = '\0';
	
		strcpy(newdest, destpath);
	}
	
	read_inode(device, ufs2, ino, &dinode);
	block_list = get_block_list(device, ufs2, &dinode);
	totalsize = _ES64(dinode.di_size);
	
	if(_ES16(dinode.di_mode) & IFDIR){
		char *dirdest, *tmp;
		char nextsrc[256];
		char nextdest[MAX_PATH];
		int ret;
		struct direct direct_tmp;
		struct stat sb;

		if(using_con){
			printf("can't copy directory!\n");
			ufs_free_block_list(block_list);
			return -1;
		}

		if(!stat(newdest, &sb)){
			if((sb.st_mode & S_IFMT) != S_IFDIR){
				return -1;
			}
			dirdest = strdup(newdest);
		}
		else{
			// if(mkdir(newdest, 0777) == -1){
			if(mkdir(newdest) == -1){
				dirdest = valid_filename(newdest, 0);
				// if(mkdir(dirdest,0777) == -1){
				if(mkdir(dirdest) == -1){
					free(dirdest);
					return -1;
				}
			}
			else{
				dirdest = strdup(newdest);
			}
		}
		
		buf = malloc(_ES64(dinode.di_size) + sizeof(struct direct));
		ufs_read_data(device, ufs2, &dinode, block_list, (u8*)buf, 0, 0);
		tmp = buf;
		
		for(i = 0;; ++i){
			ret = ufs_read_direntry(tmp, &direct_tmp);
			
			if(tmp - buf >= _ES64(dinode.di_size) || !ret)
				break;
				
			tmp += ret;
			
			if(!strcmp(direct_tmp.d_name, ".") || !strcmp(direct_tmp.d_name, ".."))
				continue;

			strcpy(nextsrc, srcpath);
			
			if(srcpath[strlen(srcpath) - 1] != '/')
				strcat(nextsrc, "/");
				
			strcat(nextsrc, direct_tmp.d_name);
			strcpy(nextdest, dirdest);
			strcat(nextdest, "/");
			strcat(nextdest, direct_tmp.d_name);
			
			sprintf(string, "%s/%s", srcpath, direct_tmp.d_name);
			printf("copy -> %s\n", string);
			ufs_copy_data(device, ufs2, ino, _ES32(direct_tmp.d_ino), nextsrc, nextdest);
		}
		
		ufs_free_block_list(block_list);
		free(buf);

		return 0;
	}
	
	/* entry is file... */
	readsize = 0;
	read = 0;

	tmp = valid_filename(newdest, using_con);
	strcpy(newdest, tmp);
	free(tmp);
	
	out = fopen(newdest, "wb");
	if (!out) {
		printf("can't create file!\n");
		return -1;																			
	}
	
	buf = malloc(ufs2->fs_bsize);
	bl = block_list->blk_add;
	
	for(i = 0; readsize < totalsize; i ++){
		
		if(totalsize - readsize < ufs2->fs_bsize){
			seek_device(device, (bl[i] * ufs2->fs_fsize) + (hdd0_start * SECTOR_SIZE));
			read = read_device(device, (u8*)buf, totalsize - readsize, (bl[i] * ufs2->fs_fsize) + (hdd0_start * SECTOR_SIZE));
			fwrite(buf, 1, read, out);
			readsize += read;
		}
		else{
			seek_device(device, (bl[i] * ufs2->fs_fsize) + (hdd0_start * SECTOR_SIZE));
			read = read_device(device, (u8*)buf, ufs2->fs_bsize, (bl[i] * ufs2->fs_fsize) + (hdd0_start * SECTOR_SIZE));
			fwrite(buf, 1, read, out);
			readsize += read;
		}
		
		fprintf(stderr,"(%03lld%%)\r", readsize * 100 / totalsize);
		
	}
	
	fclose(out);
	filetime.actime = _ES64(dinode.di_atime);
	filetime.modtime = _ES64(dinode.di_mtime);
	utime(newdest, &filetime);
	
	free(buf);
	ufs_free_block_list(block_list);
	
	return 0;
}
/***********************************************************************
*Funktion: copy patched file back to hdd
* 	s32 device        = *hdd
* 	struct fs *fs     = struct fs
* 	ufs_inop root_ino = root
* 	ufs_inop ino      = 
* 	char *path        = 
***********************************************************************/
s32 ufs_replace_data(HANDLE device, struct fs *ufs2, ufs_inop root_ino, ufs_inop ino, char *path)
{
	struct ufs2_dinode dinode;
	s64 i, size, totalsize, done = 0, n_write = 0;
	ufs2_block_list *block_list = NULL;
	u8 *buf_fd = NULL;
	FILE *fd = NULL;
	s64 *bl;
	
	
	if(strlen(path) == 1 && path[0] == 0x2F)
		return 0;
	
	if(!root_ino || !ino){
		printf("can't copy, no such file or directory!\n");
		return -1;
	}
	 
	if((fd = fopen(strrchr(path, '/') + 1, "rb")) == NULL) {
		printf("can't open patched file!\n");
		return 0;
	}
	
	fseek(fd, 0, SEEK_END);
	size = ftell(fd);
	fseek(fd, 0, SEEK_SET);
	 
	read_inode(device, ufs2, ino, &dinode);
	
	if(_ES16(dinode.di_mode) & IFDIR) {
		printf("not a file!\n");
		return 0;
	}
	totalsize = _ES64(dinode.di_size);
	
	if(size != totalsize) {
		printf("file size wrong!\n");
		return 0;
	}
	 
	block_list = get_block_list(device, ufs2, &dinode);
	buf_fd = malloc(ufs2->fs_bsize);
	bl = block_list->blk_add;
	
	
	for(i = 0; done < totalsize; i++) {
		if(totalsize - done < ufs2->fs_bsize) {  
			fseek(fd, done, SEEK_SET);
			fread(buf_fd, sizeof(u8), totalsize - done, fd);
			n_write = write_device(device, buf_fd, totalsize - done, (bl[i] * ufs2->fs_fsize) + (hdd0_start * SECTOR_SIZE));
			done += n_write;
		}
		else {  
			fseek(fd, done, SEEK_SET);
			fread(buf_fd, sizeof(u8), ufs2->fs_bsize, fd);
			n_write = write_device(device, buf_fd, ufs2->fs_bsize, (bl[i] * ufs2->fs_fsize) + (hdd0_start * SECTOR_SIZE));
			done += n_write;
		}
		
		fprintf(stderr,"(%03lld%%)\r", done * 100 / totalsize);
	}
	
	free(buf_fd);
	fclose(fd);
	
	return 0;
}
#ifdef DUMP
/*! Decrypt sectors. */
void decrypt_all_sectors(const s8 *out_file, const s8 *in_file, u64 start_sector, u64 num_sectors, u8 *ata_k1, u8 *ata_k2, u8 *edec_k1, u8 *edec_k2, BOOL is_phat, BOOL is_vflash)
{
	FILE *in;
	FILE *out;
	aes_xts_ctxt_t xts_ctxt;
	// aes_xts_ctxt_t xts_ctx_vf;
	aes_context aes_ctxt;
	// aes_context cbc_ctx;
	u64 i;
	u64 chunk_size;
	u64 position = 0;
	u64 sectors_to_read = num_sectors;
	u8 *zero_iv = (u8 *)malloc(sizeof(u8) * 0x10);
	u8 *buffer = (u8 *)malloc(sizeof(u8) * BUFFER_SIZE);
	while (sectors_to_read > 0)
	{
		//Read file to buffer.
		in = fopen(in_file, "rb");
		fseek(in, position, SEEK_SET);
		if (sectors_to_read >= (BUFFER_SIZE / SECTOR_SIZE))
			chunk_size = BUFFER_SIZE;
		else 
			chunk_size = (sectors_to_read * SECTOR_SIZE);
		fread(buffer, (size_t)chunk_size, 1, in);
		fclose(in);
		//Decrypt buffer.
		for(i = 0; i < (chunk_size / SECTOR_SIZE); i++)
		{
			//Decrypt sector.
			if (is_vflash == TRUE)
			{
				if (is_phat == TRUE)
				{
					//Set key for AES-CBC
					aes_setkey_dec(&aes_ctxt, edec_k1, 128);
					//Decrypt CBC sector.
					memset(zero_iv, 0, 0x10);
					aes_crypt_cbc(&aes_ctxt, AES_DECRYPT, SECTOR_SIZE, zero_iv, (buffer + (SECTOR_SIZE * i)), buffer + (SECTOR_SIZE * i));
					//XOR initial block in sector with sector index value.
					buffer[(SECTOR_SIZE * i)+0x8] ^= ((u64)((position / SECTOR_SIZE)+start_sector + i) >> 56 & 0xFF);
					buffer[(SECTOR_SIZE * i)+0x9] ^= ((u64)((position / SECTOR_SIZE)+start_sector + i) >> 48 & 0xFF);
					buffer[(SECTOR_SIZE * i)+0xA] ^= ((u64)((position / SECTOR_SIZE)+start_sector + i) >> 40 & 0xFF);
					buffer[(SECTOR_SIZE * i)+0xB] ^= ((u64)((position / SECTOR_SIZE)+start_sector + i) >> 32 & 0xFF);
					buffer[(SECTOR_SIZE * i)+0xC] ^= ((u64)((position / SECTOR_SIZE)+start_sector + i) >> 24 & 0xFF);
					buffer[(SECTOR_SIZE * i)+0xD] ^= ((u64)((position / SECTOR_SIZE)+start_sector + i) >> 16 & 0xFF);
					buffer[(SECTOR_SIZE * i)+0xE] ^= ((u64)((position / SECTOR_SIZE)+start_sector + i) >> 8 & 0xFF);
					buffer[(SECTOR_SIZE * i)+0xF] ^= ((u64)((position / SECTOR_SIZE)+start_sector + i) & 0xFF);
				}
				else
				{
					//Init AES-XTS context.
					aes_xts_init(&xts_ctxt, AES_DECRYPT, edec_k1, edec_k2, 128);
					//Decrypt XTS sector.
					aes_xts_crypt(&xts_ctxt, (u64)((position / SECTOR_SIZE) + i + start_sector), SECTOR_SIZE, (buffer + (SECTOR_SIZE * i)), buffer + (SECTOR_SIZE * i));
				}
			}
			else
			{
				if (is_phat == TRUE)
				{
					//Swap endian for ata only.				
					_es16_buffer(buffer + (SECTOR_SIZE * i), SECTOR_SIZE);
					//Set key for AES-CBC
					aes_setkey_dec(&aes_ctxt, ata_k1, 192);
					//Decrypt CBC sector.
					memset(zero_iv, 0, 0x10);
					aes_crypt_cbc(&aes_ctxt, AES_DECRYPT, SECTOR_SIZE, zero_iv, (buffer + (SECTOR_SIZE * i)), buffer + (SECTOR_SIZE * i));
				}
				else
				{
					//Swap endian for ata only.
					_es16_buffer(buffer + (SECTOR_SIZE * i), SECTOR_SIZE);
					//Init AES-XTS context.
					aes_xts_init(&xts_ctxt, AES_DECRYPT, ata_k1, ata_k2, 128);
					//Decrypt XTS sector.
					aes_xts_crypt(&xts_ctxt, (u64)((position / SECTOR_SIZE) + i + start_sector), SECTOR_SIZE, (buffer + (SECTOR_SIZE * i)), buffer + (SECTOR_SIZE * i));
				}
			}
		}
		//Write buffer to file
		out = fopen(out_file, "r+b");
		fseek(out, position, SEEK_SET);
		fwrite(buffer, (size_t)chunk_size, 1, out);
		fclose(out);
		//Updating vars.
		position += chunk_size;
		sectors_to_read -= (u64)(chunk_size / SECTOR_SIZE);
	}
}
#endif


/*! main */
int main(int argc, char* argv[]) {
	u8 *eid_root_key = {0};				/* root key */
	HANDLE device = NULL;				/* device handle */
	struct fs *ufs2;					/* superblock(UFS2) */
	struct fat_bs *fat_fs;              /* bootsector(FAT12/16) */
	struct fat32_bs *fat32;           	/* bootsector(FAT32) */
	ufs_inop ino;
	ufs_inop root_ino = ROOTINO;
	u8 *buf;
	if(argc <= 1){
		usage();
		goto end;
	}
	/* load rootkey from file */
/* 	if(argv[5] && strcmp(argv[5], "a") == 0){
		if((eid_root_key = _read_buffer((s8*)"erka", NULL)) == NULL){		
			printf("file \"erka\" not found !\n");
			goto end;
		}
	}
	else if(argv[5] && strcmp(argv[5], "n") == 0){
		if((eid_root_key = _read_buffer((s8*)"erkn", NULL)) == NULL){		
			printf("file \"erkn\" not found !\n");
			goto end;
		}
	} */
	if((eid_root_key = _read_buffer((s8*)"erk", NULL)) == NULL){		
		printf("file \"erk\" not found !\n");
		goto end;
	}
	/* generate ata/encdec keys */
	generate_ata_keys(eid_root_key, eid_root_key + 0x20, ata_k1, ata_k2);		
	generate_encdec_keys(eid_root_key, eid_root_key + 0x20, encdec_key1, encdec_key2);
	printf("\n\n");
	printf("HDD Decryption keys:\n");
	_print_buf(ata_k1, 0, 2);
	_print_buf(ata_k2, 0, 2);
	_print_buf(encdec_key1, 0, 2);
	_print_buf(encdec_key2, 0, 2);
	printf("\n");
	if(argv[1]){
		if(strcmp(argv[1], "file") == 0){
			if((device = get_file_handle()) == NULL)
				goto end;
		}	
		if(strcmp(argv[1], "hdd") == 0){
			if((device = get_hdd_handle()) == NULL)
				goto end;
		}
	}
	/* search all partitions */
	get_partitions(device);
	// if(argc == 2 && strcmp(argv[1], "hdd") == 0){
	if(argc == 2){
		printf("\navailable volumes are...\n\n");
		if(hdd0_start != 0){
			printf(" dev_hdd0\n");
		}
		if(hdd1_start != 0){
			printf(" dev_hdd1\n");
		}
		if(flash_start != 0){
			printf(" dev_flash\n");
		}
		if(flash2_start != 0){
			printf(" dev_flash2\n");
		}
		if(flash3_start != 0){
			printf(" dev_flash3\n");
		}
	}
	/* NOTHING/RESERVED */
	if(argc == 3){
		print_volume_info(device, argv[2]);
		goto end;
	}
	/* DEBUG: sector print */
	if(argc == 4){
		if(strcmp(argv[3], "print") == 0){
			buf= malloc(SECTOR_SIZE);
			u64 show = atoll(argv[4]);
			
			seek_device(device, show * SECTOR_SIZE);
			read_device(device, buf, SECTOR_SIZE, show * SECTOR_SIZE);
			_print_buf(buf, 0, 32);
		}
	}
	if(argc == 5){
		/* if partition dev_hdd0... */
		if(strcmp(argv[2], "dev_hdd0") == 0 && hdd0_start != 0){
			/* init gameOS... */
			ufs2 = ufs2_init(device);
			if(ufs2 == NULL){
				if(strcmp(argv[3], "print") == 0){
			printf("print....\n");
		}
			}
			if(strcmp(argv[3], "dir") == 0 || strcmp(argv[3], "ls") == 0){    		        /* show dir... */
				ufs_print_dir_list(device, ufs2, (u8*)argv[4], (u8*)argv[2]);    
				free(ufs2);
			}
			else if(strcmp(argv[3], "copy") == 0 || strcmp(argv[3], "cp") == 0){	        /* copy file/dir... */
				ino = ufs_lookup_path(device, ufs2, (u8*)argv[4], 0, ROOTINO);
				ufs_copy_data(device, ufs2, root_ino, ino, argv[4], 0);
				free(ufs2);
			}
/* 			else if(strcmp(argv[3], "paste") == 0 || strcmp(argv[3], "pa") == 0){	        // paste file/dir... //
				ino = ufs_lookup_path(device, ufs2, (u8*)argv[4], 0, ROOTINO);
				ufs_copy_data(device, ufs2, root_ino, ino, argv[4], argv[4]);
				free(ufs2);
			} */
			else{
				free(ufs2);
			}
		}
		/* if partition dev_hdd1... */
		else if(strcmp(argv[2], "dev_hdd1") == 0){
			fat32 = init_fat32(device, hdd1_start);
			if(fat32 == NULL){
				printf("can't open dev_hdd1!\n");
			}
			hdd1_free = fat_how_free_bytes(device, hdd1_start, 0, fat32);
			if(strcmp(argv[3], "dir") == 0 || strcmp(argv[3], "ls") == 0){				  			/* show dir... */
				fat_print_dir_list(device, hdd1_start, 0, fat32, (u8*)argv[4], (u8*)argv[2], hdd1_free);
				free(fat32);
			}
			else if(strcmp(argv[3], "copy") == 0 || strcmp(argv[3], "cp") == 0){	  			/* copy file/dir... */
				fat_copy_data(device, hdd1_start, 0, fat32, argv[4], 0);
				free(fat32);
			}
			else{
				free(fat32);
			}
		}
		/* if partition dev_flash... */
		else if(strcmp(argv[2], "dev_flash") == 0){
			fat_fs = init_fat_old(device, flash_start);
			if(fat_fs == NULL){
				printf("can't open dev_flash!\n");
			}	
			flash_free = fat_how_free_bytes(device, flash_start, fat_fs, 0);
			if(strcmp(argv[3], "dir") == 0 || strcmp(argv[3], "ls") == 0){
				fat_print_dir_list(device, flash_start, fat_fs, 0, (u8*)argv[4], (u8*)argv[2], flash_free);
				free(fat_fs);	
			}
			else if(strcmp(argv[3], "copy") == 0 || strcmp(argv[3], "cp") == 0){
				fat_copy_data(device, flash_start, fat_fs, 0, argv[4], 0);
				free(fat_fs);
			}
			else{
				free(fat_fs);
			}
		}
		/* if partition dev_flash2... */
		else if(strcmp(argv[2], "dev_flash2") == 0){
			fat_fs = init_fat_old(device, flash2_start);
			if(fat_fs == NULL){
				printf("can't open dev_flash2!\n");
			}
			flash2_free = fat_how_free_bytes(device, flash2_start, fat_fs, 0);
			if(strcmp(argv[3], "dir") == 0 || strcmp(argv[3], "ls") == 0){
				fat_print_dir_list(device, flash2_start, fat_fs, 0, (u8*)argv[4], (u8*)argv[2], flash2_free);
				free(fat_fs);
			}
			else if(strcmp(argv[3], "copy") == 0 || strcmp(argv[3], "cp") == 0){
				fat_copy_data(device, flash2_start, fat_fs, 0, argv[4], 0);
				free(fat_fs);
			}
			else{
				free(fat_fs);
			}
		}
		/* if partition dev_flash3... */
		else if(strcmp(argv[2], "dev_flash3") == 0){
			fat_fs = init_fat_old(device, flash3_start);
			if(fat_fs == NULL){
				printf("can't open dev_flash3!\n");
			}
			flash3_free = fat_how_free_bytes(device, flash3_start, fat_fs, 0);
			if(strcmp(argv[3], "dir") == 0 || strcmp(argv[3], "ls") == 0){
				fat_print_dir_list(device, flash3_start, fat_fs, 0, (u8*)argv[4], (u8*)argv[2], flash3_free);
				free(fat_fs);	
			}
			else if(strcmp(argv[3], "copy") == 0 || strcmp(argv[3], "cp") == 0){
				fat_copy_data(device, flash3_start, fat_fs, 0, argv[4], 0);
				free(fat_fs);	
			}
			else{
				free(fat_fs);	
			}
		}
		else{
			printf("no such volume!\n");
		}
		// DEBUG: dump sector/s to file
		// hdd_reader file dump 0x0 0x200
		if(strcmp(argv[2], "dump") == 0) {
			  s64 sec_num = strtoll(argv[3], NULL, 16);
			  s64 sec_count = strtoll(argv[4], NULL, 16);
			  FILE *fd = fopen(strcat(argv[3], ".bin"), "wb");
			  u8 *buf = malloc(sec_count * SECTOR_SIZE);
			  read_device(device, buf, (sec_count * SECTOR_SIZE), (sec_num * SECTOR_SIZE));
			  fwrite(buf, sizeof(u8), (sec_count * SECTOR_SIZE), fd);
			  free(buf);
			  fclose(fd);
		}
	}
end:
	if(device) CloseHandle(device);
	free(eid_root_key);
	return 0;
}

