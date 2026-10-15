/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Tests actual production rasterizer: coordinate types, clearing, subsampled
 * chroma, separate alpha, descriptor bounds and aligned target height. */
#include "../qemu/nikon-gpu.h"
static unsigned checks;
#define CHECK(c) do { checks++; if (!(c)) { fprintf(stderr,"FAIL line%d: %s\n",__LINE__,#c); return 1; } } while(0)
static uint32_t fbits(float f) { uint32_t v; memcpy(&v,&f,4); return v; }
static NikonGPUPath *rectangle(unsigned type, bool indirect, unsigned state) {
    NikonGPUPath *p = g_new0(NikonGPUPath,1); p->valid=true;
    p->segments=g_byte_array_new(); p->coordinates=g_byte_array_new();
    p->edges=g_array_new(false,false,sizeof(NikonGPUEdge));
    uint8_t seg[]={2,4,4,4,0}; int points[]={0,0,8,0,8,6,0,6};
    p->regs[3]=5|(indirect?0x10000000:0); p->regs[5]=8|(type<<30);
    p->regs[0x65]=state;
    p->regs[0x5c]=fbits(1); p->regs[0x5d]=fbits(10);
    if (!(state&0x100)) { p->regs[0x47]=p->regs[0x48]=fbits(4); }
    p->regs[0x41]=p->regs[0x45]=p->regs[0x49]=p->regs[0x5e]=fbits(1);
    g_byte_array_append(p->segments,seg,sizeof(seg));
    unsigned bytes=indirect && type<2?1U<<type:4;
    for(unsigned i=0;i<8;i++) { uint32_t v=type==3?fbits(points[i]):points[i]; g_byte_array_append(p->coordinates,(uint8_t*)&v,bytes); }
    nikon_gpu_flatten(p); return p;
}
int main(void) {
    AddressSpace private_memory={0};
    NikonGPU g={.memory=&private_memory};
    for(unsigned type=0;type<4;type++) {
        for(unsigned state=0x2100;state<=0x3100;state+=0x1000) {
            NikonGPUPath *p=rectangle(type,true,state);
            CHECK(p->valid && p->edges->len==4);
            NikonGPUEdge e=g_array_index(p->edges,NikonGPUEdge,1);
            CHECK(e.x0==8 && e.y0==0 && e.x1==8 && e.y1==6);
            nikon_gpu_path_free(p);
        }
    }
    NikonGPUPath *p=rectangle(2,false,0x100);
    uint32_t r[512]={0}; r[0x1a3]=(8<<16)|8; r[0xc0]=7<<16; r[0xc1]=7<<16;
    r[0x184]=8; r[0x1a4]=0xa1001000; r[0x185]=0xffffffff;
    for(unsigned format=0x105;format<=0x107;format++) {
        for(unsigned a4=0;a4<=(format==0x107);a4++) {
            unsigned bpp=format==0x105?1:2, n=48*bpp, n2=a4?24:48;
            memset(memory,0xa5,sizeof(memory));
            r[0x1a2]=format|(a4<<24); r[0x1b5]=r[0x1a4]+n;
            /* Native visible y=2..8 maps to six stored rows, like6..688
             * maps to682. Packed106 has no second-plane height bound. */
            for(unsigned j=0;j<p->edges->len;j++) {
                NikonGPUEdge *e=&g_array_index(p->edges,NikonGPUEdge,j);
                e->y0=e->uy0+(format==0x106?0:2);
                e->y1=e->uy1+(format==0x106?0:2);
            }
            r[0x185]=0xffffffff;
            CHECK(nikon_gpu_draw(&g,r,p));
            uint8_t *a=memory+0x1000,*b=a+n, pixel[4];
            for(unsigned i=0;i<48;i++) {
                nikon_gpu_pixel_read(a,b,format,a4,i,pixel);
                CHECK(pixel[0]>=254 && pixel[1]>=254 && pixel[2]>=254 && pixel[3]==255);
            }
            CHECK(a[-1]==0xa5);
            CHECK((format==0x106 ? a[8*8*2] : b[n2])==0xa5);
            r[0x185]=0;
            CHECK(nikon_gpu_draw(&g,r,p));
            nikon_gpu_pixel_read(a,b,format,a4,0,pixel);
            CHECK(pixel[0]==0 && pixel[1]==0 && pixel[2]==0);
            CHECK(pixel[3]==(format==0x107?0:255));
            if(format!=0x106) {
                uint8_t saved[256]; memcpy(saved,a,sizeof(saved));
                r[0x1b5]=0;
                CHECK(!nikon_gpu_draw(&g,r,p));
                CHECK(!memcmp(saved,a,sizeof(saved)));
            }
        }
    }
    /* One final chroma average for two red pixels, no alternating tint. */
    r[0x1a2]=0x105; r[0x1b5]=r[0x1a4]+48; r[0x185]=0xff0000ff;
    CHECK(nikon_gpu_draw(&g,r,p));
    CHECK(memory[0x1000]==82 && memory[0x1001]==82);
    CHECK(memory[0x1030]==90 && memory[0x1031]==240);
    /* Source-over transparent paint preserves the destination exactly. */
    r[0x1a2]=0; r[0x185]=0; r[0x1a0]=0x00010000;
    for(unsigned j=0;j<p->edges->len;j++) {
        NikonGPUEdge *e=&g_array_index(p->edges,NikonGPUEdge,j); e->y0=e->uy0; e->y1=e->uy1;
    }
    memset(memory+0x1000,0x80,256); uint8_t saved[256]; memcpy(saved,memory+0x1000,256);
    CHECK(nikon_gpu_draw(&g,r,p)); CHECK(!memcmp(saved,memory+0x1000,256));
    r[0x1a0]=0; CHECK(nikon_gpu_draw(&g,r,p));
    CHECK(!memcmp(memory+0x1000,(uint8_t[192]){0},192));
    nikon_gpu_path_free(p);
    /* A black stroke remains outside a subsequent white fill. Closed paths
     * have an empty center; miter corners must cover the outside corner. */
    p=rectangle(2,false,0x2000);
    CHECK(p->valid && p->edges->len>4);
    memset(r,0,sizeof(r)); r[0x1a3]=(16<<16)|16;
    r[0xc0]=r[0xc1]=15<<16; r[0x1a4]=0xa1001000; r[0x184]=8;
    r[0x185]=0xff000000; r[0x1a0]=0x00010000;
    memset(memory+0x1000,0,16*16*4);
    CHECK(nikon_gpu_draw(&g,r,p));
    #define PIX(x,y,c) memory[0x1000+((y)*16+(x))*4+(c)]
    CHECK(PIX(3,6,3)==255 && PIX(3,6,0)==0);
    CHECK(PIX(8,7,3)==0);
    CHECK(PIX(3,3,3)==255);
    CHECK(PIX(2,2,3)==0);
    NikonGPUPath *fill=rectangle(2,false,0x2100);
    for(unsigned j=0;j<fill->edges->len;j++) {
        NikonGPUEdge *e=&g_array_index(fill->edges,NikonGPUEdge,j);
        e->x0+=4;e->x1+=4;e->y0+=4;e->y1+=4;
    }
    r[0x185]=0xffffffff;
    CHECK(nikon_gpu_draw(&g,r,fill));
    CHECK(PIX(8,7,0)==255 && PIX(8,7,3)==255);
    CHECK(PIX(3,6,0)==0 && PIX(3,6,3)==255);
    nikon_gpu_path_free(fill);
    /* Open L: no invented closing diagonal, butt/round/square caps. */
    g_byte_array_set_size(p->segments,3); p->regs[3]=3; p->regs[5]=6|(2U<<30);
    for(unsigned cap=0;cap<3;cap++) {
        g_array_set_size(p->edges,0);p->contour=0;p->regs[0x65]=0x2000|(cap<<16);
        nikon_gpu_flatten(p); CHECK(p->valid);
        memset(memory+0x1000,0,16*16*4);r[0x185]=0xff000000;
        CHECK(nikon_gpu_draw(&g,r,p));
        CHECK(PIX(8,7,3)==0);
        CHECK(cap==0?PIX(3,4,3)==0:PIX(3,4,3)>0);
        if(cap==2) { CHECK(PIX(3,3,3)==255); }
    }
    /* Width is transformed with user space (2x horizontal, 1x vertical). */
    g_array_set_size(p->edges,0);p->contour=0;p->regs[0x65]=0x2000;
    p->regs[0x41]=fbits(2);p->regs[0x5c]=fbits(.5);
    nikon_gpu_flatten(p);CHECK(p->valid);
    double minx=1e9,maxx=-1e9,miny=1e9;
    for(unsigned j=0;j<p->edges->len;j++) {
        NikonGPUEdge e=g_array_index(p->edges,NikonGPUEdge,j);
        minx=MIN(minx,MIN(e.x0,e.x1));maxx=MAX(maxx,MAX(e.x0,e.x1));miny=MIN(miny,MIN(e.y0,e.y1));
    }
    CHECK(fabs(minx-4)<1e-6 && fabs(maxx-21)<1e-6 && fabs(miny-3.5)<1e-6);
    g_array_set_size(p->edges,0);p->regs[0x5a]=1;
    nikon_gpu_flatten(p);CHECK(!p->valid);
    nikon_gpu_path_free(p);
    printf("PASS %u synthetic renderer checks\n",checks); return 0;
}
