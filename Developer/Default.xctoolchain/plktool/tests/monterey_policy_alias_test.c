
#include "../monterey_policy_alias.h"
#include <stdio.h>
static unsigned checks,failures;
#define CHECK(x) do {checks++; if(!(x)){failures++;fprintf(stderr,"line%d: %s\n",__LINE__,#x);}}while(0)
static unsigned char *load(const char *path,size_t *size)
{
 FILE *f=fopen(path,"rb");unsigned char *b;long n;
 if(!f)return NULL;
 if(fseek(f,0,SEEK_END)||(n=ftell(f))<0||fseek(f,0,SEEK_SET)){fclose(f);return NULL;}
 b=malloc(n);if(!b){fclose(f);return NULL;}
 if(fread(b,1,n,f)!=(size_t)n){free(b);fclose(f);return NULL;}
 fclose(f);*size=n;return b;
}
static void rejected(const unsigned char *b,size_t n)
{
 unsigned char *out=(unsigned char *)1;size_t outsize=99;
 CHECK(!ravyn_clone_monterey_dsep_alias(b,n,&out,&outsize));
 CHECK(out==NULL&&outsize==0);
}
int main(int argc,char **argv)
{
 size_t n,dn,cn,en,ecn,aliassize=0;unsigned char *b,*d,*c,*e,*ec,*alias=NULL,*before,*bad;
 size_t sc=0,sg=0,entry=0;uint32_t so,ns,st,sz;
 if(argc!=6 && argc!=7 && argc!=8)return 2;
 CHECK(!ravyn_monterey_image4_identity(NULL,0));
 if(argc==8){size_t z=0;unsigned char *a=load(argv[7],&z);if(!a)return 2;CHECK(ravyn_monterey_image4_identity(a,z));a[0]^=1;CHECK(!ravyn_monterey_image4_identity(a,z));free(a);}
 CHECK(!ravyn_monterey_amfi_identity(NULL,0));
 if(argc>=7){size_t z=0;unsigned char *a=load(argv[6],&z);if(!a)return 2;CHECK(ravyn_monterey_amfi_identity(a,z));a[0]^=1;CHECK(!ravyn_monterey_amfi_identity(a,z));free(a);}
 b=load(argv[1],&n);d=load(argv[2],&dn);c=load(argv[3],&cn);
 e=load(argv[4],&en);ec=load(argv[5],&ecn);
 if(!b||!d||!c||!e||!ec)return 2;
 before=malloc(n);bad=malloc(n);if(!before||!bad)return 2;
 memcpy(before,b,n);
 CHECK(ravyn_monterey_sandbox_identity(d,dn));
 CHECK(!ravyn_monterey_sandbox_identity(c,cn));
 d[0]^=1;CHECK(!ravyn_monterey_sandbox_identity(d,dn));d[0]^=1;
 CHECK(!ravyn_monterey_sandbox_identity(NULL,0));
 CHECK(ravyn_monterey_endpointsecurity_identity(e,en));
 CHECK(!ravyn_monterey_endpointsecurity_identity(ec,ecn));
 e[0]^=1;CHECK(!ravyn_monterey_endpointsecurity_identity(e,en));e[0]^=1;
 CHECK(!ravyn_monterey_endpointsecurity_identity(NULL,0));
 CHECK(ravyn_clone_monterey_dsep_alias(b,n,&alias,&aliassize));
 CHECK(alias&&aliassize==n+sizeof("_mac_policy_register_v80"));
 CHECK(!memcmp(b,before,n));
 if(!alias)return 1;
 for(size_t o=32,i=0;i<ravyn_alias_u32(b+16);o+=ravyn_alias_u32(b+o+4),i++){
  if(ravyn_alias_u32(b+o)==2)sc=o;
  if(ravyn_alias_u32(b+o)==25)sg=o;
 }
 so=ravyn_alias_u32(b+sc+8);ns=ravyn_alias_u32(b+sc+12);
 st=ravyn_alias_u32(b+sc+16);sz=ravyn_alias_u32(b+sc+20);
 for(uint32_t i=0;i<ns;i++)if(!strcmp((char *)b+st+ravyn_alias_u32(b+so+i*16),"_mac_policy_register"))entry=so+i*16;
 CHECK(entry!=0);
 CHECK(alias[entry+4]==0xb&&alias[entry+5]==0);
 CHECK(ravyn_alias_u64(alias+entry+8)==sz);
 CHECK(!strcmp((char *)alias+st+ravyn_alias_u64(alias+entry+8),"_mac_policy_register_v80"));
 CHECK(ravyn_alias_u32(alias+sc+8)==so&&ravyn_alias_u32(alias+sc+12)==ns&&ravyn_alias_u32(alias+sc+16)==st);
 CHECK(ravyn_alias_u32(alias+sc+20)==sz+sizeof("_mac_policy_register_v80"));
 CHECK(ravyn_alias_u64(alias+sg+48)==ravyn_alias_u64(b+sg+48)+sizeof("_mac_policy_register_v80"));
 CHECK(!ravyn_clone_monterey_dsep_alias(b,n,NULL,&aliassize));
 CHECK(!ravyn_clone_monterey_dsep_alias(b,n,&alias,NULL));
 free(alias);alias=NULL;
 rejected(NULL,0);rejected(b,31);rejected(b,n-1);
 memcpy(bad,b,n);bad[0]^=1;rejected(bad,n);
 memcpy(bad,b,n);ravyn_alias_put32(bad+4,0x100000c);rejected(bad,n);
 memcpy(bad,b,n);ravyn_alias_put32(bad+16,4);rejected(bad,n);
 memcpy(bad,b,n);bad[entry+4]=0xf;rejected(bad,n);
 memcpy(bad,b,n);bad[entry+5]=1;rejected(bad,n);
 memcpy(bad,b,n);bad[entry+6]=1;rejected(bad,n);
 memcpy(bad,b,n);ravyn_alias_put64(bad+entry+8,1);rejected(bad,n);
 memcpy(bad,b,n);ravyn_alias_put32(bad+entry,sz);rejected(bad,n);
 memcpy(bad,b,n);ravyn_alias_put32(bad+so,ravyn_alias_u32(b+entry));rejected(bad,n);
 memcpy(bad,b,n);ravyn_alias_put32(bad+entry,0);rejected(bad,n);
 memcpy(bad,b,n);ravyn_alias_put32(bad+sc+20,UINT32_MAX);rejected(bad,n);
 memcpy(bad,b,n);ravyn_alias_put32(bad+sc+12,UINT32_MAX);rejected(bad,n);
 memcpy(bad,b,n);ravyn_alias_put32(bad+32+4,7);rejected(bad,n);
 memcpy(bad,b,n);ravyn_alias_put64(bad+sg+48,UINT64_MAX);rejected(bad,n);
 CHECK(!memcmp(b,before,n));
 printf("MONTEREY_POLICY_ALIAS_UNIT checks=%u failures=%u\n",checks,failures);
 free(b);free(d);free(c);free(e);free(ec);free(before);free(bad);return failures?1:0;
}
