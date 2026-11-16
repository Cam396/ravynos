/*
 * Copyright (c) 2012 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/*
 * NOTICE: This file was modified for the ravynOS macOS bring-up project
 * (2026-10-18 to 2026-11-15). Included in support of clause 2.2(b) of the
 * Apple Public Source License, Version 2.0.
 */

#include <libkern/libkern.h>
#include <libkern/crypto/register_crypto.h>
#include <libkern/crypto/crypto_internal.h>
#include <libkern/section_keywords.h>

SECURITY_READ_ONLY_LATE(crypto_functions_t) g_crypto_funcs = NULL;

int
register_crypto_functions(const crypto_functions_t funcs)
{
	if (g_crypto_funcs) {
		return -1;
	}

	g_crypto_funcs = funcs;

	return 0;
}

/* Exact, explicitly selected Monterey registration ABI. Its table removed
 * seven legacy slots. Ordinary legacy registration above stays unchanged.
 * Removed slots are unavailable through this interface; there are no in-tree
 * consumers of those slots. Never reinterpret modern RNG/RSA callbacks as
 * legacy RC4/CAST/padding callbacks. */
struct ravyn_crypto_functions_v21 {
	/* digests common functions */
	ccdigest_init_fn_t ccdigest_init_fn;
	ccdigest_update_fn_t ccdigest_update_fn;
	ccdigest_final_fn_t ccdigest_final_fn;
	ccdigest_fn_t ccdigest_fn;
	/* digest implementations */
	const struct ccdigest_info * ccmd5_di;
	const struct ccdigest_info * ccsha1_di;
	const struct ccdigest_info * ccsha256_di;
	const struct ccdigest_info * ccsha384_di;
	const struct ccdigest_info * ccsha512_di;

	/* hmac common function */
	cchmac_init_fn_t cchmac_init_fn;
	cchmac_update_fn_t cchmac_update_fn;
	cchmac_final_fn_t cchmac_final_fn;
	cchmac_fn_t cchmac_fn;

	/* ciphers modes implementations */
	/* AES, ecb, cbc and xts */
	const struct ccmode_ecb *ccaes_ecb_encrypt;
	const struct ccmode_ecb *ccaes_ecb_decrypt;
	const struct ccmode_cbc *ccaes_cbc_encrypt;
	const struct ccmode_cbc *ccaes_cbc_decrypt;
	const struct ccmode_ctr *ccaes_ctr_crypt;
	const struct ccmode_xts *ccaes_xts_encrypt;
	const struct ccmode_xts *ccaes_xts_decrypt;
	const struct ccmode_gcm *ccaes_gcm_encrypt;
	const struct ccmode_gcm *ccaes_gcm_decrypt;

	ccgcm_init_with_iv_fn_t ccgcm_init_with_iv_fn;
	ccgcm_inc_iv_fn_t ccgcm_inc_iv_fn;

	ccchacha20poly1305_fns_t ccchacha20poly1305_fns;

	/* DES, ecb and cbc */
	const struct ccmode_ecb *ccdes_ecb_encrypt;
	const struct ccmode_ecb *ccdes_ecb_decrypt;
	const struct ccmode_cbc *ccdes_cbc_encrypt;
	const struct ccmode_cbc *ccdes_cbc_decrypt;
	/* Triple DES, ecb and cbc */
	const struct ccmode_ecb *cctdes_ecb_encrypt;
	const struct ccmode_ecb *cctdes_ecb_decrypt;
	const struct ccmode_cbc *cctdes_cbc_encrypt;
	const struct ccmode_cbc *cctdes_cbc_decrypt;
	/* DES key helper functions */
	ccdes_key_is_weak_fn_t ccdes_key_is_weak_fn;
	ccdes_key_set_odd_parity_fn_t ccdes_key_set_odd_parity_fn;
	/* CTS3 padding+encrypt functions */
	ccpad_cts3_crypt_fn_t ccpad_cts3_encrypt_fn;
	ccpad_cts3_crypt_fn_t ccpad_cts3_decrypt_fn;

	/* rng */
	ccrng_fn_t ccrng_fn;

	/* rsa */
	ccrsa_make_pub_fn_t        ccrsa_make_pub_fn;
	ccrsa_verify_pkcs1v15_fn_t ccrsa_verify_pkcs1v15_fn;
};
static struct crypto_functions ravyn_crypto_v21_legacy_view;

int
register_crypto_functions_v21(const struct ravyn_crypto_functions_v21 *funcs)
{
    if (!funcs || g_crypto_funcs) return -1;
    struct crypto_functions translated = {0};
    translated.ccdigest_init_fn = funcs->ccdigest_init_fn;
    translated.ccdigest_update_fn = funcs->ccdigest_update_fn;
    translated.ccdigest_final_fn = funcs->ccdigest_final_fn;
    translated.ccdigest_fn = funcs->ccdigest_fn;
    translated.ccmd5_di = funcs->ccmd5_di;
    translated.ccsha1_di = funcs->ccsha1_di;
    translated.ccsha256_di = funcs->ccsha256_di;
    translated.ccsha384_di = funcs->ccsha384_di;
    translated.ccsha512_di = funcs->ccsha512_di;
    translated.cchmac_init_fn = funcs->cchmac_init_fn;
    translated.cchmac_update_fn = funcs->cchmac_update_fn;
    translated.cchmac_final_fn = funcs->cchmac_final_fn;
    translated.cchmac_fn = funcs->cchmac_fn;
    translated.ccaes_ecb_encrypt = funcs->ccaes_ecb_encrypt;
    translated.ccaes_ecb_decrypt = funcs->ccaes_ecb_decrypt;
    translated.ccaes_cbc_encrypt = funcs->ccaes_cbc_encrypt;
    translated.ccaes_cbc_decrypt = funcs->ccaes_cbc_decrypt;
    translated.ccaes_ctr_crypt = funcs->ccaes_ctr_crypt;
    translated.ccaes_xts_encrypt = funcs->ccaes_xts_encrypt;
    translated.ccaes_xts_decrypt = funcs->ccaes_xts_decrypt;
    translated.ccaes_gcm_encrypt = funcs->ccaes_gcm_encrypt;
    translated.ccaes_gcm_decrypt = funcs->ccaes_gcm_decrypt;
    translated.ccgcm_init_with_iv_fn = funcs->ccgcm_init_with_iv_fn;
    translated.ccgcm_inc_iv_fn = funcs->ccgcm_inc_iv_fn;
    translated.ccchacha20poly1305_fns = funcs->ccchacha20poly1305_fns;
    translated.ccdes_ecb_encrypt = funcs->ccdes_ecb_encrypt;
    translated.ccdes_ecb_decrypt = funcs->ccdes_ecb_decrypt;
    translated.ccdes_cbc_encrypt = funcs->ccdes_cbc_encrypt;
    translated.ccdes_cbc_decrypt = funcs->ccdes_cbc_decrypt;
    translated.cctdes_ecb_encrypt = funcs->cctdes_ecb_encrypt;
    translated.cctdes_ecb_decrypt = funcs->cctdes_ecb_decrypt;
    translated.cctdes_cbc_encrypt = funcs->cctdes_cbc_encrypt;
    translated.cctdes_cbc_decrypt = funcs->cctdes_cbc_decrypt;
    translated.ccdes_key_is_weak_fn = funcs->ccdes_key_is_weak_fn;
    translated.ccdes_key_set_odd_parity_fn = funcs->ccdes_key_set_odd_parity_fn;
    translated.ccpad_cts3_encrypt_fn = funcs->ccpad_cts3_encrypt_fn;
    translated.ccpad_cts3_decrypt_fn = funcs->ccpad_cts3_decrypt_fn;
    translated.ccrng_fn = funcs->ccrng_fn;
    translated.ccrsa_make_pub_fn = funcs->ccrsa_make_pub_fn;
    translated.ccrsa_verify_pkcs1v15_fn = funcs->ccrsa_verify_pkcs1v15_fn;
    ravyn_crypto_v21_legacy_view = translated;
    g_crypto_funcs = &ravyn_crypto_v21_legacy_view;
    return 0;
}
