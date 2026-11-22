/* ko_slide_patch: add KASLR slide to a relinked KSU .ko (ABS symbols + ksustub quads) */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint16_t r16(const uint8_t *p){ return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t r32(const uint8_t *p){ return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24); }
static uint64_t r64(const uint8_t *p){ uint64_t v=0; for(int i=7;i>=0;i--) v=(v<<8)|p[i]; return v; }
static void w64(uint8_t *p, uint64_t v){ for(int i=0;i<8;i++){ p[i]=(uint8_t)(v&0xff); v>>=8; } }

static int in_kernel(uint64_t v){ return v >= 0xffffff8000000000ULL; }

int main(int argc, char **argv){
    if(argc < 4){ fprintf(stderr,"usage: %s <base.ko> <out.ko> <slide-hex>\n",argv[0]); return 2; }
    const char *src=argv[1], *dst=argv[2];
    uint64_t slide=strtoull(argv[3],0,0);

    FILE *f=fopen(src,"rb"); if(!f){ perror("open"); return 1; }
    fseek(f,0,SEEK_END); long n=ftell(f); fseek(f,0,SEEK_SET);
    uint8_t *d=malloc((size_t)n); if(!d){ perror("malloc"); return 1; }
    if(fread(d,1,(size_t)n,f)!=(size_t)n){ perror("read"); return 1; }
    fclose(f);

    if(n < 64 || memcmp(d,"\x7f""ELF",4)!=0 || d[4]!=2 || d[5]!=1){
        fprintf(stderr,"not ELF64 LE\n"); return 1;
    }
    uint64_t shoff=r64(d+0x28); uint16_t shentsize=r16(d+0x3a), shnum=r16(d+0x3c), shstrndx=r16(d+0x3e);
    if(!shoff || !shnum || shentsize < 64 || shoff + (uint64_t)shnum*shentsize > (uint64_t)n){
        fprintf(stderr,"bad section table\n"); return 1;
    }
    uint64_t shstr_off=0;
    { uint8_t *s=d+shoff+(uint64_t)shstrndx*shentsize; shstr_off=r64(s+0x18); }
    if(!shstr_off || shstr_off >= (uint64_t)n){ fprintf(stderr,"bad shstrtab\n"); return 1; }

    int symidx=-1; uint64_t sym_best=0;
    int stubidx=-1;
    for(int i=0;i<shnum;i++){
        uint8_t *s=d+shoff+(uint64_t)i*shentsize;
        uint32_t nameoff=r32(s); uint32_t type=r32(s+4);
        uint64_t off=r64(s+0x18), size=r64(s+0x20);
        const char *name=(const char*)(d+shstr_off+nameoff);
        if(type==2 && off > sym_best && off + size <= (uint64_t)n){ sym_best=off; symidx=i; }
        if(name && strcmp(name,".text.ksustub")==0 && off + size <= (uint64_t)n) stubidx=i;
    }
    if(symidx<0){ fprintf(stderr,"no symtab\n"); return 1; }
    uint8_t *symsh=d+shoff+(uint64_t)symidx*shentsize;
    uint64_t sym_off=r64(symsh+0x18), sym_size=r64(symsh+0x20);
    uint64_t sym_ent=r64(symsh+0x38); if(sym_ent < 24) sym_ent=24;
    uint32_t sym_link=r32(symsh+0x28);
    uint8_t *strsh=d+shoff+(uint64_t)sym_link*shentsize;
    uint64_t str_off=r64(strsh+0x18);

    int nsym=0, nstub=0;
    /* Patch every SHT_SYMTAB copy: offrelink6.py patches the original in place
       and appends a second (updated) copy at EOF; both must carry the slide. */
    for(int si=0; si<shnum; si++){
        uint8_t *ss=d+shoff+(uint64_t)si*shentsize;
        if(r32(ss+4)!=2) continue;
        uint64_t so=r64(ss+0x18), sz=r64(ss+0x20), se=r64(ss+0x38);
        if(se<24) se=24;
        if(so+sz > (uint64_t)n) continue;
        for(uint64_t o=so; o+24<=so+sz; o+=se){
            uint8_t *e=d+o;
            uint16_t shndx=r16(e+6); uint64_t val=r64(e+8);
            if(shndx==0xfff1 && in_kernel(val)){ w64(e+8, val+slide); nsym++; }
        }
    }
    if(stubidx>=0){
        uint8_t *s=d+shoff+(uint64_t)stubidx*shentsize;
        uint64_t off=r64(s+0x18), size=r64(s+0x20);
        for(uint64_t o=off; o+8<=off+size; o+=8){
            uint64_t v=r64(d+o);
            if(in_kernel(v)){ w64(d+o, v+slide); nstub++; }
        }
    }
    /* find _printk for verification */
    uint64_t printk=0; int found=0;
    if(str_off < (uint64_t)n){
        for(uint64_t o=sym_off; o+24<=sym_off+sym_size; o+=sym_ent){
            uint8_t *e=d+o; uint32_t no=r32(e);
            if(str_off+no >= (uint64_t)n) continue;
            const char *name=(const char*)(d+str_off+no);
            if(strcmp(name,"_printk")==0){ printk=r64(e+8); found=1; break; }
        }
    }
    FILE *g=fopen(dst,"wb"); if(!g){ perror("create"); return 1; }
    if(fwrite(d,1,(size_t)n,g)!=(size_t)n){ perror("write"); fclose(g); return 1; }
    fclose(g); free(d);
    printf("slide=0x%llx abs_symbols=%d stub_quads=%d _printk=0x%llx%s\n",
           (unsigned long long)slide, nsym, nstub, (unsigned long long)printk, found?"":" (notfound)");
    return 0;
}
