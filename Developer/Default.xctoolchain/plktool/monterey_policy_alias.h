/*
 * Opt-in, exact-donor link interface adaptation. No executable bytes are changed.
 * This helper is independent of CoreFoundation for direct host unit testing.
 */
#ifndef RAVYN_MONTEREY_POLICY_ALIAS_H
#define RAVYN_MONTEREY_POLICY_ALIAS_H
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <openssl/sha.h>

#define RAVYN_MONTEREY_SANDBOX_SHA256 \
 "1a8465056f12799d6de02a5f42836d62411e4bf9edcfc654799fa5a45184f2c1"
#define RAVYN_MONTEREY_ENDPOINTSECURITY_SHA256 \
 "9c78dbf3c1204a2b6460694e8ce0e99b3e588573c4a0cd5348828bd0a0b1a47d"
#define RAVYN_MONTEREY_AMFI_SHA256 "9994015cfdfb231c56c54af14b5ce3a05e4269bd2a1448f21cf6c5c8ebaa3394"
static int ravyn_monterey_amfi_identity(const unsigned char *data, size_t size)
{
    static const unsigned char expected[32] = {0x99,0x94,0x01,0x5c,0xfd,0xfb,0x23,0x1c,0x56,0xc5,0x4a,0xf1,0x4b,0x5c,0xe3,0xa0,0x5e,0x42,0x69,0xbd,0x2a,0x14,0x48,0xf2,0x1c,0xf6,0xc5,0xc8,0xeb,0xaa,0x33,0x94};
    unsigned char digest[SHA256_DIGEST_LENGTH];
    return data && SHA256(data, size, digest) && !memcmp(digest, expected, 32);
}
#define RAVYN_MONTEREY_IMAGE4_SHA256 "1f6349fa84c8099e92362944423de12bddff29c05ce3a6fcf3314afc9fac3ed4"
static int ravyn_monterey_image4_identity(const unsigned char *data, size_t size)
{
 static const unsigned char expected[32] = {0x1f,0x63,0x49,0xfa,0x84,0xc8,0x09,0x9e,0x92,0x36,0x29,0x44,0x42,0x3d,0xe1,0x2b,0xdd,0xff,0x29,0xc0,0x5c,0xe3,0xa6,0xfc,0xf3,0x31,0x4a,0xfc,0x9f,0xac,0x3e,0xd4};
 unsigned char digest[SHA256_DIGEST_LENGTH];
 return data && SHA256(data,size,digest) && !memcmp(digest,expected,32);
}
static uint32_t ravyn_alias_u32(const unsigned char *p)
{ uint32_t v; memcpy(&v,p,4); return v; }
static uint64_t ravyn_alias_u64(const unsigned char *p)
{ uint64_t v; memcpy(&v,p,8); return v; }
static void ravyn_alias_put32(unsigned char *p,uint32_t v)
{ memcpy(p,&v,4); }
static void ravyn_alias_put64(unsigned char *p,uint64_t v)
{ memcpy(p,&v,8); }
static int ravyn_alias_range(size_t off,size_t len,size_t size)
{ return off <= size && len <= size-off; }
static int ravyn_monterey_sandbox_identity(const unsigned char *data,size_t size)
{
    static const unsigned char expected[32]={
        0x1a,0x84,0x65,0x05,0x6f,0x12,0x79,0x9d,
        0x6d,0xe0,0x2a,0x5f,0x42,0x83,0x6d,0x62,
        0x41,0x1e,0x4b,0xf9,0xed,0xcf,0xc6,0x54,
        0x79,0x9f,0xa5,0xa4,0x51,0x84,0xf2,0xc1};
    unsigned char digest[SHA256_DIGEST_LENGTH];
    return data && SHA256(data,size,digest) && !memcmp(digest,expected,32);
}
static int ravyn_monterey_endpointsecurity_identity(const unsigned char *data,size_t size)
{
    static const unsigned char expected[32]={
        0x9c,0x78,0xdb,0xf3,0xc1,0x20,0x4a,0x2b,
        0x64,0x60,0x69,0x4e,0x8c,0xe0,0xe9,0x9b,
        0x3e,0x58,0x85,0x73,0xc4,0xa0,0xcd,0x53,
        0x48,0x82,0x8b,0xd0,0xa0,0xb1,0xa4,0x7d};
    unsigned char digest[SHA256_DIGEST_LENGTH];
    return data && SHA256(data,size,digest) && !memcmp(digest,expected,32);
}
/*
 * Only accepts our simple little-endian x86_64 kernel interface layout:
 * one sectionless __LINKEDIT segment, one symbol table, one UUID command.
 * Output belongs to caller. On any failure outputs stay NULL/0.
 */
static int ravyn_clone_monterey_dsep_alias(const unsigned char *input,size_t size,
                                         unsigned char **out,size_t *outsize)
{
    static const char source[]="_mac_policy_register";
    static const char target[]="_mac_policy_register_v80";
    size_t cursor=32,symcmd=0,segcmd=0,uuidcmd=0,aliasentry=0;
    uint32_t ncmds,cmdbytes,symoff,nsyms,stroff,strsize;
    unsigned matches=0,segments=0,symtabs=0,uuids=0;
    unsigned char *copy;
    if(!out || !outsize) return 0;
    *out=NULL; *outsize=0;
    if(!input || size<32 || ravyn_alias_u32(input)!=0xfeedfacf ||
       ravyn_alias_u32(input+4)!=0x01000007 ||
       ravyn_alias_u32(input+12)!=11) return 0;
    ncmds=ravyn_alias_u32(input+16); cmdbytes=ravyn_alias_u32(input+20);
    if(ncmds!=3 || !ravyn_alias_range(32,cmdbytes,size)) return 0;
    for(uint32_t i=0;i<ncmds;i++) {
        uint32_t cmd,len;
        if(!ravyn_alias_range(cursor,8,32+(size_t)cmdbytes)) return 0;
        cmd=ravyn_alias_u32(input+cursor);
        len=ravyn_alias_u32(input+cursor+4);
        if(len<8 || !ravyn_alias_range(cursor,len,32+(size_t)cmdbytes))return 0;
        if(cmd==25 && len==72) {
            if(memcmp(input+cursor+8,"__LINKEDIT\0\0\0\0\0\0",16) ||
               ravyn_alias_u32(input+cursor+64)!=0) return 0;
            segcmd=cursor; segments++;
        } else if(cmd==2 && len==24) {symcmd=cursor;symtabs++;}
        else if(cmd==27 && len==24) {uuidcmd=cursor;uuids++;}
        else return 0;
        cursor+=len;
    }
    if(cursor!=32+(size_t)cmdbytes || segments!=1 || symtabs!=1 || uuids!=1)return 0;
    symoff=ravyn_alias_u32(input+symcmd+8);
    nsyms=ravyn_alias_u32(input+symcmd+12);
    stroff=ravyn_alias_u32(input+symcmd+16);
    strsize=ravyn_alias_u32(input+symcmd+20);
    if(!ravyn_alias_range(symoff,(size_t)nsyms*16,size) ||
       symoff+(size_t)nsyms*16!=stroff ||
       !ravyn_alias_range(stroff,strsize,size) || stroff+(size_t)strsize!=size ||
       size>UINT32_MAX-sizeof(target) || strsize>UINT32_MAX-sizeof(target))return 0;
    if(ravyn_alias_u64(input+segcmd+40)>size ||
       ravyn_alias_u64(input+segcmd+48)!=size-ravyn_alias_u64(input+segcmd+40) ||
       ravyn_alias_u64(input+segcmd+32)>UINT64_MAX-sizeof(target))return 0;
    for(uint32_t i=0;i<nsyms;i++) {
        size_t entry=symoff+(size_t)i*16;
        uint32_t strx=ravyn_alias_u32(input+entry);
        const unsigned char *name;
        if(strx>=strsize || !memchr(input+stroff+strx,0,strsize-strx))return 0;
        name=input+stroff+strx;
        if(!strcmp((const char *)name,source)) {
            matches++; aliasentry=entry;
            if(input[entry+4]!=1 || input[entry+5]!=0 ||
               input[entry+6]!=0 || input[entry+7]!=0 ||
               ravyn_alias_u64(input+entry+8)!=0) return 0;
        }
    }
    if(matches!=1)return 0;
    copy=(unsigned char *)malloc(size+sizeof(target));
    if(!copy)return 0;
    memcpy(copy,input,size); memcpy(copy+size,target,sizeof(target));
    copy[aliasentry+4]=0x0b; /* N_INDR | N_EXT */
    ravyn_alias_put64(copy+aliasentry+8,strsize);
    ravyn_alias_put32(copy+symcmd+20,strsize+sizeof(target));
    ravyn_alias_put64(copy+segcmd+32,ravyn_alias_u64(copy+segcmd+32)+sizeof(target));
    ravyn_alias_put64(copy+segcmd+48,ravyn_alias_u64(copy+segcmd+48)+sizeof(target));
    /* UUID identifies the private interface, not the unchanged donor executable. */
    {
        unsigned char digest[SHA256_DIGEST_LENGTH];
        if(!SHA256(copy,size+sizeof(target),digest)){free(copy);return 0;}
        memcpy(copy+uuidcmd+8,digest,16);
    }
    *out=copy; *outsize=size+sizeof(target); return 1;
}
#endif
