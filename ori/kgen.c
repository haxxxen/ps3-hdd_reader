/*
* Copyright (c) 2012 by naehrwert
* This file is released under the GPLv2.
*/

#include "types.h"
#include "aes.h"

//encdec data key seed
u8 encdec_seed_00[] =
{
	0xE2, 0xD0, 0x5D, 0x40, 0x71, 0x94, 0x5B, 0x01, 0xC3, 0x6D, 0x51, 0x51, 0xE8, 0x8C, 0xB8, 0x33,
  0x4A, 0xAA, 0x29, 0x80, 0x81, 0xD8, 0xC4, 0x4F, 0x18, 0x5D, 0xC6, 0x60, 0xED, 0x57, 0x56, 0x86
};

//encdec tweak key seed
u8 encdec_seed_20[] =
{
	0x02, 0x08, 0x32, 0x92, 0xC3, 0x05, 0xD5, 0x38, 0xBC, 0x50, 0xE6, 0x99, 0x71, 0x0C, 0x0A, 0x3E,
  0x55, 0xF5, 0x1C, 0xBA, 0xA5, 0x35, 0xA3, 0x80, 0x30, 0xB6, 0x7F, 0x79, 0xC9, 0x05, 0xBD, 0xA3

};

//sb indiv seed 0x00-0x1F
u8 sb_indiv_seed_00[] =
{
	0xD9, 0x2D, 0x65, 0xDB, 0x05, 0x7D, 0x49, 0xE1, 0xA6, 0x6F, 0x22, 0x74, 0xB8, 0xBA, 0xC5, 0x08,
  0x83, 0x84, 0x4E, 0xD7, 0x56, 0xCA, 0x79, 0x51, 0x63, 0x62, 0xEA, 0x8A, 0xDA, 0xC6, 0x03, 0x26
};

//sb indiv seed 0x20-0x3F
u8 sb_indiv_seed_20[] =
{
	0xC3, 0xB3, 0xB5, 0xAA, 0xCC, 0x74, 0xCD, 0x6A, 0x48, 0xEF, 0xAB, 0xF4, 0x4D, 0xCD, 0xF1, 0x6E,
  0x37, 0x9F, 0x55, 0xF5, 0x77, 0x7D, 0x09, 0xFB, 0xEE, 0xDE, 0x07, 0x05, 0x8E, 0x94, 0xBE, 0x08
};

void generate_ata_keys(u8 *eid_root_key, u8 *eid_root_iv, u8 *data_key_dst, u8 *tweak_key_dst)
{
	
	aes_context aes_ctxt;
	u8 iv[0x10];

	//Generate ATA data key.
	aes_setkey_enc(&aes_ctxt, eid_root_key, 0x100);
	memcpy(iv, eid_root_iv, 0x10);
	aes_crypt_cbc(&aes_ctxt, AES_ENCRYPT, 0x20, iv, sb_indiv_seed_00, data_key_dst);
	
	//Generate ATA tweak key.
	aes_setkey_enc(&aes_ctxt, eid_root_key, 0x100);
	memcpy(iv, eid_root_iv, 0x10);
	aes_crypt_cbc(&aes_ctxt, AES_ENCRYPT, 0x20, iv, sb_indiv_seed_20, tweak_key_dst);
}

void generate_encdec_keys(u8 *eid_root_key, u8 *eid_root_iv, u8 *data_key_dst, u8 *tweak_key_dst)
{
	aes_context aes_ctxt;
	u8 iv[0x10];

	//Generate encdec_k1.
	aes_setkey_enc(&aes_ctxt, eid_root_key, 0x100);
	memcpy(iv, eid_root_iv, 0x10);
	aes_crypt_cbc(&aes_ctxt, AES_ENCRYPT, 0x20, iv, encdec_seed_00, data_key_dst);

	//Generate encdec_k3.
	aes_setkey_enc(&aes_ctxt, eid_root_key, 0x100);
	memcpy(iv, eid_root_iv, 0x10);
	aes_crypt_cbc(&aes_ctxt, AES_ENCRYPT, 0x20, iv, encdec_seed_20, tweak_key_dst);
}
