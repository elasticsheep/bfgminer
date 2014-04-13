#include "config.h"

#include <math.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#ifndef WIN32
  #include <sys/mman.h>
  #include <sys/select.h>
  #include <termios.h>
  #include <sys/stat.h>
  #include <fcntl.h>
  #ifndef O_CLOEXEC
    #define O_CLOEXEC 0
  #endif
#else
  #include "compat.h"
  #include <windows.h>
  #include <io.h>
#endif

#include "deviceapi.h"
#include "miner.h"

#include "driver-sockit.h"

static void work_to_sockit_payload(struct sockit_payload *p, struct work *w);
static bool fudge_nonce(struct work * const work, uint32_t *nonce_p);

#define LWHPS2FPGA_BRIDGE_BASE   (0xff200000)
#define AVALON_MINER_BRIDGE_BASE (LWHPS2FPGA_BRIDGE_BASE + 0x0000)

BFG_REGISTER_DRIVER(sockit_drv)

uint32_t regs_buffer[256];

static
void sockit_drv_init(void)
{
	for (int i = 0; i < 256; i++)
		regs_buffer[i] = 0;

	regs_buffer[0x80] = 0x000004ff;
}

static
void sockit_drv_detect(void)
{
	applog(LOG_INFO, "INFO: sockit_detect");

	uint32_t *regs = regs_buffer;
	int fd;
	fd = open("/dev/mem",O_RDWR|O_SYNC);
	if (fd < 0)
	{
		applog(LOG_INFO, "/dev/mem trouble");
	}
	else
	{
		regs = mmap(0,4096,PROT_READ|PROT_WRITE,MAP_SHARED,fd,AVALON_MINER_BRIDGE_BASE);
		if (regs == MAP_FAILED)
			applog(LOG_INFO, "regs mmap trouble");
		close(fd);
	}

	uint32_t miner_info = regs[0x80];
	if (miner_info == 0xFFFFFFFF)
	{
		applog(LOG_INFO, "SOCKIT: Invalid miner info");
		regs = regs_buffer;
	}

	applog(LOG_INFO, "SOCKIT: miner_info = 0x%08x version = %i hashers = %i", miner_info, miner_info & 0xFF, (miner_info >> 8) & 0xFF);
	applog(LOG_INFO, "SOCKIT: miner version = %i", miner_info & 0xFF);
	applog(LOG_INFO, "SOCKIT: %i hashers", (miner_info >> 8) & 0xFF);

	struct cgpu_info *cgpu;
	cgpu = malloc(sizeof(*cgpu));
	*cgpu = (struct cgpu_info){
			.drv = &sockit_drv,
			.procs = 1,
			.threads = 1,
		};

	add_cgpu(cgpu);
}

static
bool sockit_thread_init(struct thr_info *thr)
{
	struct cgpu_info * const cgpu = thr->cgpu;
	struct cgpu_info *proc;
	struct sockit_device *sockit;

	applog(LOG_INFO, "SOCKIT: sockit_thread_init");

	uint32_t *regs = regs_buffer;
	int fd;
	fd = open("/dev/mem",O_RDWR|O_SYNC);
	if (fd < 0)
	{
		applog(LOG_INFO, "/dev/mem trouble");
	}
	else
	{
		regs = mmap(0,4096,PROT_READ|PROT_WRITE,MAP_SHARED,fd,AVALON_MINER_BRIDGE_BASE);
		if (regs == MAP_FAILED)
			applog(LOG_INFO, "regs mmap trouble");
		close(fd);
	}

	/* Reset the registers */
	for (int i = 0; i < 128; i++)
		regs[i] = 0x00000000;

	for (proc = cgpu; proc; proc = proc->next_proc)
	{
		sockit = malloc(sizeof(*sockit));
		*sockit = (struct sockit_device){
			.regs = regs,
		};
		
		proc->device_data = sockit;
	}

	timer_set_now(&thr->tv_poll);
	
	return true;
}

static double DIFFEXACTONE = 26959946667150639794667015087019630673637144422540572481103610249215.0;
static const uint64_t diffone = 0xFFFF000000000000ull;

static void bdiff_target_leadzero(unsigned char *target, double diff)
{
	uint64_t *data64, h64;
	double d64;

	d64 = diffone;
	d64 /= diff;
	d64 = ceil(d64);
	h64 = d64;

	memset(target, 0, 32);
	if (d64 < 18446744073709551616.0) {
		unsigned char *rtarget = target;
		memset(rtarget, 0, 32);
		if (opt_scrypt)
			data64 = (uint64_t *)(rtarget + 2);
		else
			data64 = (uint64_t *)(rtarget + 4);
		*data64 = htobe64(h64);
	} else {
		/* Support for the classic all FFs just-below-1 diff */
		if (opt_scrypt)
			memset(&target[2], 0xff, 30);
		else
			memset(&target[4], 0xff, 28);
	}
}

static
bool sockit_job_prepare(struct thr_info *thr, struct work *work, __maybe_unused uint64_t max_nonce)
{
	struct cgpu_info * const proc = thr->cgpu;
	struct sockit_device * const sockit = proc->device_data;

	applog(LOG_INFO, "SOCKIT: sockit_job_prepare");

	char hex[153];
	bin2hex(hex, &work->data[0], 76);
	applog(LOG_INFO, "%"PRIpreprv": Preparing work %s", proc->proc_repr, hex);

	unsigned char flipped_data[80];
	swap32yes(flipped_data, work->data, 80 / 4);

	applog(LOG_INFO, "+");

	memcpy(sockit->midstate, work->midstate, 32);
	sockit->block1[0] = bswap_32(*(unsigned *)(flipped_data + 64));
	sockit->block1[1] = bswap_32(*(unsigned *)(flipped_data + 68));
	sockit->block1[2] = bswap_32(*(unsigned *)(flipped_data + 72));

	sockit->start_nonce = bswap_32(*(unsigned *)(flipped_data + 76));

	unsigned int rtarget[8];
	bdiff_target_leadzero((unsigned char *)rtarget, work->sdiff);

	char htarget[65];
	bin2hex(htarget, (unsigned char *)rtarget, 32);
	applog(LOG_DEBUG, "Generated target %s", htarget);

	sockit->target[0] = rtarget[0];
	sockit->target[1] = rtarget[1];
	sockit->target[2] = rtarget[2];
	sockit->target[3] = rtarget[3];
	sockit->target[4] = rtarget[4];
	sockit->target[5] = rtarget[5];
	sockit->target[6] = rtarget[6];
	sockit->target[7] = rtarget[7];

	work->blk.nonce = 0xffffffff;
	return true;
}

static
void sockit_job_start(struct thr_info __maybe_unused * const thr)
{
	struct cgpu_info *proc = thr->cgpu;
	struct sockit_device * const sockit = proc->device_data;

	applog(LOG_INFO, "SOCKIT: sockit_job_start");

	sockit->regs[0] = sockit->midstate[0];
	sockit->regs[1] = sockit->midstate[1];
	sockit->regs[2] = sockit->midstate[2];
	sockit->regs[3] = sockit->midstate[3];
	sockit->regs[4] = sockit->midstate[4];
	sockit->regs[5] = sockit->midstate[5];
	sockit->regs[6] = sockit->midstate[6];
	sockit->regs[7] = sockit->midstate[7];

	sockit->regs[16] = sockit->block1[0];
	sockit->regs[17] = sockit->block1[1];
	sockit->regs[18] = sockit->block1[3];

	sockit->regs[19] = sockit->target[0];
	sockit->regs[20] = sockit->target[1];
	sockit->regs[21] = sockit->target[2];
	sockit->regs[22] = sockit->target[3];
	sockit->regs[23] = sockit->target[4];
	sockit->regs[24] = sockit->target[5];
	sockit->regs[25] = sockit->target[6];
	sockit->regs[26] = sockit->target[7];

	// Nonce ranges
	sockit->regs[28] = sockit->start_nonce;
	sockit->regs[29] = 0xFFFFFFFF;
	sockit->regs[30] = sockit->start_nonce;
	sockit->regs[31] = 0xFFFFFFFF;
	sockit->regs[32] = sockit->start_nonce;
	sockit->regs[33] = 0xFFFFFFFF;
	sockit->regs[34] = sockit->start_nonce;
	sockit->regs[35] = 0xFFFFFFFF;

	// Start the nonce search
	sockit->regs[27] = 0x1;

	for (int i = 0; i < 36; i++)
	{
		applog(LOG_INFO, "SOCKIT: [%i] = 0x%08x", i, sockit->regs[i]);
	}
}

static
void sockit_poll(struct thr_info * const master_thr)
{
	struct cgpu_info *proc;
	struct thr_info *thr;
	struct sockit_device *sockit;
	struct timeval tv_now;

	applog(LOG_INFO, "SOCKIT: sockit_do_io");

	proc = master_thr->cgpu;
	thr = proc->thr[0];
	sockit = proc->device_data;

	// Check the miner status
	uint32_t status = sockit->regs[129];
	uint32_t nonce = sockit->regs[130];
	
	applog(LOG_INFO, "SOCKIT: status = 0x%08x", status);
	applog(LOG_INFO, "SOCKIT: nonce = 0x%08x", nonce);
    for (int i = 0; i < 4; i++)
	    applog(LOG_INFO, "SOCKIT: current[%i] = 0x%08x", i, sockit->regs[131 + i]);
	    
	if (status & 0x2)
	{
		if (fudge_nonce(thr->work, &nonce))
		{
			applog(LOG_INFO, "%"PRIpreprv": nonce = %08lx (work=%p)",
						 proc->proc_repr, (unsigned long)nonce, thr->work);
			submit_nonce(thr, thr->work, nonce);
		}
		else
		{
			applog(LOG_INFO, "SOCKIT: Invalid nonce");
		}
	}

	// Arm the timer for the next poll
	timer_set_delay(&master_thr->tv_poll, &tv_now, 10000); // us
}

static
int64_t sockit_job_process_results(struct thr_info *thr, struct work *work, bool stopping)
{
	applog(LOG_INFO, "SOCKIT: sockit_job_process_results");
	// Bitfury chips process only 768/1024 of the nonce range
	return 0xbd000000;
}

struct device_drv sockit_drv = {
	.dname = "sockit",
	.name = "SOC",
	.drv_init = sockit_drv_init,
	.drv_detect = sockit_drv_detect,

	.thread_init = sockit_thread_init,

	.minerloop = minerloop_async,
	.job_prepare = sockit_job_prepare,
	.job_start = sockit_job_start,
	.poll = sockit_poll,
	.job_process_results = sockit_job_process_results,
};

bool fudge_nonce(struct work * const work, uint32_t *nonce_p) {
	static const uint32_t offsets[] = {0, 0xffc00000, 0xff800000, 0x02800000, 0x02C00000, 0x00400000};
	uint32_t nonce;
	int i;
	
	if (unlikely(!work))
		return false;
	
	for (i = 0; i < 6; ++i)
	{
		nonce = *nonce_p + offsets[i];
		if (test_nonce(work, nonce, false))
		{
			*nonce_p = nonce;
			return true;
		}
	}
	return false;
}
