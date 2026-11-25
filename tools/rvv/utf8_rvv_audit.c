#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
extern int utf8_range_IsValid(const char*, size_t);
extern size_t utf8_range_ValidPrefix(const char*, size_t);
static size_t golden(const unsigned char* s, size_t n) {
  size_t i = 0;
  while (i < n) {
    unsigned b0 = s[i];
    if (b0 <= 0x7F) { i += 1; continue; }
    if (b0 >= 0xC2 && b0 <= 0xDF) { if (i+1<n && s[i+1]>=0x80 && s[i+1]<=0xBF) { i+=2; continue; } return i; }
    if (b0 >= 0xE0 && b0 <= 0xEF) { if (i+2>=n) return i;
      unsigned a=s[i+1], b=s[i+2];
      if (a<0x80||a>0xBF||b<0x80||b>0xBF) return i;
      if (b0==0xE0 && a<0xA0) return i;
      if (b0==0xED && a>0x9F) return i;
      i += 3; continue; }
    if (b0 >= 0xF0 && b0 <= 0xF4) { if (i+3>=n) return i;
      unsigned a=s[i+1], b=s[i+2], c=s[i+3];
      if (a<0x80||a>0xBF||b<0x80||b>0xBF||c<0x80||c>0xBF) return i;
      if (b0==0xF0 && a<0x90) return i;
      if (b0==0xF4 && a>0x8F) return i;
      i += 4; continue; }
    return i;
  }
  return i;
}
int main(void) {
  unsigned char buf[256]; int bad=0, cases=0;
  /* A: SIMD path (remainder >= 64 non-ASCII bytes): repeat a 3-byte codepoint 24 times */
  for (unsigned lead=0xE0; lead<=0xEF; lead++) for (unsigned b2=0x80; b2<=0xBF; b2++) {
    for (int k=0;k<24;k++){ buf[3*k]=lead; buf[3*k+1]=b2; buf[3*k+2]=0x80; }
    size_t n=72, g=golden(buf,n); int v=utf8_range_IsValid((const char*)buf,n); cases++;
    if ((g==n)!=v) { if(bad<12) printf("A-MISMATCH lead=%02X b2=%02X golden_valid=%d got_valid=%d\n",lead,b2,g==n,v); bad++; }
  }
  for (unsigned lead=0xF0; lead<=0xF4; lead++) for (unsigned b2=0x80; b2<=0xBF; b2++) {
    for (int k=0;k<18;k++){ buf[4*k]=lead; buf[4*k+1]=b2; buf[4*k+2]=0x80; buf[4*k+3]=0x80; }
    size_t n=72, g=golden(buf,n); int v=utf8_range_IsValid((const char*)buf,n); cases++;
    if ((g==n)!=v) { if(bad<12) printf("A-MISMATCH4 lead=%02X b2=%02X golden_valid=%d got_valid=%d\n",lead,b2,g==n,v); bad++; }
  }
  printf("A(simd-path range rules): cases=%d mismatches=%d\n",cases,bad);
  /* B: short input preceded by hostile bytes in memory */
  bad=0; cases=0;
  const unsigned pre[5]={0x80,0xC3,0xE1,0xF0,0x41};
  for(int p=0;p<5;p++) for(int cls=0;cls<3;cls++) for(size_t n=1;n<=80;n++){
    unsigned char* d=buf+1; buf[0]=pre[p];
    for(size_t k=0;k<n;k++){
      if(cls==0) d[k]= (k%3==0)?0xE1:(k%3==1)?0x80:0x81;     /* valid-ish 3-byte, truncated at end */
      else if(cls==1) d[k]= (k%2==0)?0xC2:0x41;            /* C2 41 invalid pairs */
      else d[k]=0x80;                                      /* lone continuation */
    }
    size_t g=golden(d,n); int v=utf8_range_IsValid((const char*)d,n); size_t pr=utf8_range_ValidPrefix((const char*)d,n); cases++;
    if((g==n)!=v || g!=pr){ if(bad<10) printf("B-MISMATCH pre=%02X cls=%d n=%zu golden_prefix=%zu got_valid=%d got_prefix=%zu\n",pre[p],cls,n,g,v,pr); bad++; }
  }
  printf("B(short input, hostile preceding byte): cases=%d mismatches=%d\n",cases,bad);
  /* C: guard page: any read before data must crash */
  size_t ps=sysconf(_SC_PAGESIZE);
  unsigned char* m=mmap(NULL,2*ps,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  unsigned char* d=m+ps; munmap(m,ps);
  bad=0; cases=0;
  for(int cls=0;cls<3;cls++) for(size_t n=1;n<=80;n++){
    for(size_t k=0;k<n;k++) d[k]= (cls==0)?0xE1:(cls==1)?0x80:0xC2;
    size_t g=golden(d,n); int v=utf8_range_IsValid((const char*)d,n); cases++;
    if((g==n)!=v){ if(bad<10) printf("C-MISMATCH cls=%d n=%zu golden=%d got=%d\n",cls,n,g==n,v); bad++; }
  }
  printf("C(guard page before data): cases=%d mismatches=%d, no crash\n",cases,bad);
  return 0;
}
