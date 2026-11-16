/* External forms of the existing corecrypto header contracts.
 * Keep the genuine legacy provider and its registration table unchanged.
 * Mode callbacks and their return values are forwarded exactly. */
#define cccbc_init ravyn_inline_cccbc_init
#define cccbc_set_iv ravyn_inline_cccbc_set_iv
#define cccbc_update ravyn_inline_cccbc_update
#define ccgcm_aad ravyn_inline_ccgcm_aad
#define ccgcm_finalize ravyn_inline_ccgcm_finalize
#define ccgcm_init ravyn_inline_ccgcm_init
#define ccgcm_set_iv ravyn_inline_ccgcm_set_iv
#define ccgcm_update ravyn_inline_ccgcm_update
#define ccoid_equal ravyn_inline_ccoid_equal
#include <corecrypto/ccmode.h>
#include <corecrypto/ccasn1.h>
#undef cccbc_init
#undef cccbc_set_iv
#undef cccbc_update
#undef ccgcm_aad
#undef ccgcm_finalize
#undef ccgcm_init
#undef ccgcm_set_iv
#undef ccgcm_update
#undef ccoid_equal

int
cccbc_init(const struct ccmode_cbc *mode, cccbc_ctx *ctx, size_t key_len, const void *key)
{
    return ravyn_inline_cccbc_init(mode, ctx, key_len, key);
}

int
cccbc_set_iv(const struct ccmode_cbc *mode, cccbc_iv *iv_ctx, const void *iv)
{
    return ravyn_inline_cccbc_set_iv(mode, iv_ctx, iv);
}

int
cccbc_update(const struct ccmode_cbc *mode, cccbc_ctx *ctx, cccbc_iv *iv, size_t nblocks, const void *in, void *out)
{
    return ravyn_inline_cccbc_update(mode, ctx, iv, nblocks, in, out);
}

int
ccgcm_aad(const struct ccmode_gcm *mode, ccgcm_ctx *ctx, size_t nbytes, const void *additional_data)
{
    return ravyn_inline_ccgcm_aad(mode, ctx, nbytes, additional_data);
}

int
ccgcm_finalize(const struct ccmode_gcm *mode, ccgcm_ctx *ctx, size_t tag_nbytes, void *tag)
{
    return ravyn_inline_ccgcm_finalize(mode, ctx, tag_nbytes, tag);
}

int
ccgcm_init(const struct ccmode_gcm *mode, ccgcm_ctx *ctx, size_t key_nbytes, const void *key)
{
    return ravyn_inline_ccgcm_init(mode, ctx, key_nbytes, key);
}

int
ccgcm_set_iv(const struct ccmode_gcm *mode, ccgcm_ctx *ctx, size_t iv_nbytes, const void *iv)
{
    return ravyn_inline_ccgcm_set_iv(mode, ctx, iv_nbytes, iv);
}

int
ccgcm_update(const struct ccmode_gcm *mode, ccgcm_ctx *ctx, size_t nbytes, const void *in, void *out)
{
    return ravyn_inline_ccgcm_update(mode, ctx, nbytes, in, out);
}

bool
ccoid_equal(ccoid_t oid1, ccoid_t oid2)
{
    return ravyn_inline_ccoid_equal(oid1, oid2);
}
