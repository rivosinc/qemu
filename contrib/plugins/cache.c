/*
 * Copyright (C) 2021, Mahmoud Mandour <ma.mandourr@gmail.com>
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */

#include <inttypes.h>
#include <stdio.h>
#include <glib.h>
#include <zlib.h>

#include <qemu-plugin.h>

#define STRTOLL(x) g_ascii_strtoll(x, NULL, 10)

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static enum qemu_plugin_mem_rw rw = QEMU_PLUGIN_MEM_RW;

static gzFile stats_file = Z_NULL;
static gzFile dump_file = Z_NULL;
bool dump_done = false;
static uint64_t intv_length = 200000000;
static uint64_t dump_icount = 200000000;
static uint64_t interval = 0;
static uint64_t drift = 0;
static uint64_t total_insns = 0;
static uint64_t cur_insns = 0;

static GHashTable *miss_ht;

static GMutex hashtable_lock;
static GRand *rng;

static int limit;
static bool sys;

enum EvictionPolicy {
    LRU,
    FIFO,
    RAND,
};

enum EvictionPolicy policy;

/*
 * A CacheSet is a set of cache blocks. A memory block that maps to a set can be
 * put in any of the blocks inside the set. The number of block per set is
 * called the associativity (assoc).
 *
 * Each block contains the stored tag and a valid bit. Since this is not
 * a functional simulator, the data itself is not stored. We only identify
 * whether a block is in the cache or not by searching for its tag.
 *
 * In order to search for memory data in the cache, the set identifier and tag
 * are extracted from the address and the set is probed to see whether a tag
 * match occur.
 *
 * An address is logically divided into three portions: The block offset,
 * the set number, and the tag.
 *
 * The set number is used to identify the set in which the block may exist.
 * The tag is compared against all the tags of a set to search for a match. If a
 * match is found, then the access is a hit.
 *
 * The CacheSet also contains bookkeaping information about eviction details.
 */

typedef struct {
    uint64_t addr;
    uint64_t tag;
    bool valid;
} CacheBlock;

typedef struct {
    CacheBlock *blocks;
    uint64_t *lru_priorities;
    uint64_t lru_gen_counter;
    GQueue *fifo_queue;
} CacheSet;

typedef struct {
    CacheSet *sets;
    int num_sets;
    int cachesize;
    int assoc;
    int blksize_shift;
    uint64_t set_mask;
    uint64_t tag_mask;
    uint64_t accesses;          /* All caches*/
    uint64_t misses;            /* All caches*/
    uint64_t iaccesses;         /* Just for the L2 instance to separate the I and D*/
    uint64_t imisses;           /* Just for the L2 instance to separate the I and D*/
    uint64_t mmisses;           /*Just for L3 cache, used for L2 reads that miss in L3*/
    uint64_t maccesses;           /*Just for L3 cache, used for L2 reads that miss in L3*/
    uint64_t vmisses;             /*Just for L3 cache, used for L2 victims that miss in L3*/
    uint64_t vaccesses;           /*Just for L3 cache, used for L2 victims that miss in L3*/
    uint64_t evictions;
} Cache;


typedef struct {
    char *disas_str;
    const char *symbol;
    uint64_t addr;
    uint64_t l1_dmisses;
    uint64_t l1_imisses;
    uint64_t l2_misses;
    uint64_t l3_misses;
} InsnData;

void (*update_hit)(Cache *cache, int set, int blk);
void (*update_miss)(Cache *cache, int set, int blk);

void (*metadata_init)(Cache *cache);
void (*metadata_destroy)(Cache *cache);

static int cores;
static Cache **l1_dcaches, **l1_icaches;

static bool use_l2;
static bool use_l3;
static Cache **l2_ucaches;
static Cache **l3_ucaches;

static GMutex *l1_dcache_locks;
static GMutex *l1_icache_locks;
static GMutex *l2_ucache_locks;
static GMutex *l3_ucache_locks;

static uint64_t l1_dmem_accesses;
static uint64_t l1_imem_accesses;
static uint64_t l1_imisses;
static uint64_t l1_dmisses;

static uint64_t l2_imem_accesses;
static uint64_t l2_dmem_accesses;
static uint64_t l2_imisses;
static uint64_t l2_iaccesses;
static uint64_t l2_dmisses;
static uint64_t l2_accesses;
static uint64_t l2_misses;
static uint64_t l3_accesses;
static uint64_t l3_maccesses;
static uint64_t l3_vaccesses;
static uint64_t l3_misses;
static uint64_t l3_mmisses;
static uint64_t l3_vmisses;

static int pow_of_two(int num)
{
    g_assert((num & (num - 1)) == 0);
    int ret = 0;
    while (num /= 2) {
        ret++;
    }
    return ret;
}

/*
 * LRU evection policy: For each set, a generation counter is maintained
 * alongside a priority array.
 *
 * On each set access, the generation counter is incremented.
 *
 * On a cache hit: The hit-block is assigned the current generation counter,
 * indicating that it is the most recently used block.
 *
 * On a cache miss: The block with the least priority is searched and replaced
 * with the newly-cached block, of which the priority is set to the current
 * generation number.
 */

static void lru_priorities_init(Cache *cache)
{
    int i;

    for (i = 0; i < cache->num_sets; i++) {
        cache->sets[i].lru_priorities = g_new0(uint64_t, cache->assoc);
        cache->sets[i].lru_gen_counter = 0;
    }
}

static void lru_update_blk(Cache *cache, int set_idx, int blk_idx)
{
    CacheSet *set = &cache->sets[set_idx];
    set->lru_priorities[blk_idx] = cache->sets[set_idx].lru_gen_counter;
    set->lru_gen_counter++;
}

static void invalidate_block(Cache *cache,int set_idx);

static int lru_get_lru_block(Cache *cache, int set_idx)
{
    int i, min_idx, min_priority;

    min_priority = cache->sets[set_idx].lru_priorities[0];
    min_idx = 0;

    for (i = 1; i < cache->assoc; i++) {
        if (cache->sets[set_idx].lru_priorities[i] < min_priority) {
            min_priority = cache->sets[set_idx].lru_priorities[i];
            min_idx = i;
        }
    }
    return min_idx;
}

static void lru_priorities_destroy(Cache *cache)
{
    int i;

    for (i = 0; i < cache->num_sets; i++) {
        g_free(cache->sets[i].lru_priorities);
    }
}

/*
 * FIFO eviction policy: a FIFO queue is maintained for each CacheSet that
 * stores accesses to the cache.
 *
 * On a compulsory miss: The block index is enqueued to the fifo_queue to
 * indicate that it's the latest cached block.
 *
 * On a conflict miss: The first-in block is removed from the cache and the new
 * block is put in its place and enqueued to the FIFO queue.
 */

static void fifo_init(Cache *cache)
{
    int i;

    for (i = 0; i < cache->num_sets; i++) {
        cache->sets[i].fifo_queue = g_queue_new();
    }
}

static int fifo_get_first_block(Cache *cache, int set)
{
    GQueue *q = cache->sets[set].fifo_queue;
    return GPOINTER_TO_INT(g_queue_pop_tail(q));
}

static void fifo_update_on_miss(Cache *cache, int set, int blk_idx)
{
    GQueue *q = cache->sets[set].fifo_queue;
    g_queue_push_head(q, GINT_TO_POINTER(blk_idx));
}

static void fifo_destroy(Cache *cache)
{
    int i;

    for (i = 0; i < cache->num_sets; i++) {
        g_queue_free(cache->sets[i].fifo_queue);
    }
}

static inline uint64_t extract_tag(Cache *cache, uint64_t addr)
{
    return addr & cache->tag_mask;
}

static inline uint64_t extract_set(Cache *cache, uint64_t addr)
{
    return (addr & cache->set_mask) >> cache->blksize_shift;
}

static const char *cache_config_error(int blksize, int assoc, int cachesize)
{
    if (cachesize % blksize != 0) {
        return "cache size must be divisible by block size";
    } else if (cachesize % (blksize * assoc) != 0) {
        return "cache size must be divisible by set size (assoc * block size)";
    } else {
        return NULL;
    }
}

static bool bad_cache_params(int blksize, int assoc, int cachesize)
{
    return (cachesize % blksize) != 0 || (cachesize % (blksize * assoc) != 0);
}

static Cache *cache_init(int blksize, int assoc, int cachesize)
{
    Cache *cache;
    int i;
    uint64_t blk_mask;

    /*
     * This function shall not be called directly, and hence expects suitable
     * parameters.
     */
    g_assert(!bad_cache_params(blksize, assoc, cachesize));

    cache = g_new(Cache, 1);
    cache->assoc = assoc;
    cache->cachesize = cachesize;
    cache->num_sets = cachesize / (blksize * assoc);
    cache->sets = g_new(CacheSet, cache->num_sets);
    cache->blksize_shift = pow_of_two(blksize);
    cache->accesses = 0;
    cache->misses = 0;
    cache->iaccesses = 0;
    cache->imisses = 0;
    cache->mmisses = 0;
    cache->vmisses = 0;
    cache->evictions = 0;

    for (i = 0; i < cache->num_sets; i++) {
        cache->sets[i].blocks = g_new0(CacheBlock, assoc);
    }

    blk_mask = blksize - 1;
    cache->set_mask = ((cache->num_sets - 1) << cache->blksize_shift);
    cache->tag_mask = ~(cache->set_mask | blk_mask);

    if (metadata_init) {
        metadata_init(cache);
    }

    return cache;
}

static Cache **caches_init(int blksize, int assoc, int cachesize)
{
    Cache **caches;
    int i;

    if (bad_cache_params(blksize, assoc, cachesize)) {
        return NULL;
    }

    caches = g_new(Cache *, cores);

    for (i = 0; i < cores; i++) {
        caches[i] = cache_init(blksize, assoc, cachesize);
    }

    return caches;
}

static int get_invalid_block(Cache *cache, uint64_t set)
{
    int i;

    for (i = 0; i < cache->assoc; i++) {
        if (!cache->sets[set].blocks[i].valid) {
            return i;
        }
    }

    return -1;
}

static int get_replaced_block(Cache *cache, int set)
{
    switch (policy) {
    case RAND:
        return g_rand_int_range(rng, 0, cache->assoc);
    case LRU:
        return lru_get_lru_block(cache, set);
    case FIFO:
        return fifo_get_first_block(cache, set);
    default:
        g_assert_not_reached();
    }
}

static int in_cache(Cache *cache, uint64_t addr)
{
    int i;
    uint64_t tag, set;

    tag = extract_tag(cache, addr);
    set = extract_set(cache, addr);

    for (i = 0; i < cache->assoc; i++) {
        if (cache->sets[set].blocks[i].tag == tag &&
                cache->sets[set].blocks[i].valid) {
            return i;
        }
    }

    return -1;
}

/**
 * access_cache(): Simulate a cache access
 * @cache: The cache under simulation
 * @addr: The address of the requested memory location
 *
 * Returns true if the requsted data is hit in the cache and false when missed.
 * The cache is updated on miss for the next access.
 */
static bool access_cache(Cache *cache, uint64_t addr)
{
    int hit_blk, replaced_blk;
    uint64_t tag, set;

    tag = extract_tag(cache, addr);
    set = extract_set(cache, addr);

    hit_blk = in_cache(cache, addr);
    if (hit_blk != -1) {
        if (update_hit) {
            update_hit(cache, set, hit_blk);
        }
        return true;
    }

    replaced_blk = get_invalid_block(cache, set);

    if (replaced_blk == -1) {
        replaced_blk = get_replaced_block(cache, set);
    }

    if (update_miss) {
        update_miss(cache, set, replaced_blk);
    }

    cache->sets[set].blocks[replaced_blk].tag = tag;
    cache->sets[set].blocks[replaced_blk].valid = true;

    return false;
}

static bool access_cache_return_victim(Cache *cache, uint64_t addr, uint64_t* victim_tag)
{
    int hit_blk, replaced_blk;
    uint64_t tag, set;
    (*victim_tag) = -1;

    tag = extract_tag(cache, addr);
    set = extract_set(cache, addr);

    hit_blk = in_cache(cache, addr);
    if (hit_blk != -1) {
        if (update_hit) {
            update_hit(cache, set, hit_blk);
        }
        return true;
    }

    replaced_blk = get_invalid_block(cache, set);

    if (replaced_blk == -1) {
        replaced_blk = get_replaced_block(cache, set);
	//(*victim_tag) = cache->sets[set].blocks[replaced_blk].tag;
	(*victim_tag) = cache->sets[set].blocks[replaced_blk].addr;
	//Increment eviction counts here
	cache->evictions++;
	//fprintf(stdout,"L2 victim tag: %lx \n",*victim_tag);

    }
    if (update_miss) {
        update_miss(cache, set, replaced_blk);
    }

    cache->sets[set].blocks[replaced_blk].tag = tag;
    cache->sets[set].blocks[replaced_blk].addr = addr;
    cache->sets[set].blocks[replaced_blk].valid = true;

    return false;
}

//The difference between this and the usual cache is we allocate only the victims
//from level-1 into this caches but lookup all of the misses from level-1
static bool access_victim_cache(Cache *cache, uint64_t addr, bool is_victim)
{
    int hit_blk, replaced_blk;
    uint64_t tag, set;

    tag = extract_tag(cache, addr);
    set = extract_set(cache, addr);
    if (!is_victim)
    {
       hit_blk = in_cache(cache,addr);
       if(hit_blk!=1)
       {
          //mark it invalid on a hit
          cache->sets[set].blocks[hit_blk].valid = false;
          cache->sets[set].blocks[hit_blk].tag = 0;
	  return true;
       }
       else return false;
    }

    //From here on its victim case
    hit_blk = in_cache(cache, addr);
    if (hit_blk != -1) {
        if (update_hit) {
            update_hit(cache, set, hit_blk);
        }
        return true;
    }
    else
    {
	    
       replaced_blk = get_invalid_block(cache, set);

       if (replaced_blk == -1) 
       {
          replaced_blk = get_replaced_block(cache, set);
	  //Increment eviction counts here
	  cache->evictions++;

       }
       if (update_miss) {
          update_miss(cache, set, replaced_blk);
       }

       cache->sets[set].blocks[replaced_blk].tag = tag;
       cache->sets[set].blocks[replaced_blk].valid = true;
    }

    return false;
}


static void vcpu_mem_access(unsigned int vcpu_index, qemu_plugin_meminfo_t info,
                            uint64_t vaddr, void *userdata)
{
    uint64_t effective_addr;
    struct qemu_plugin_hwaddr *hwaddr;
    int cache_idx;
    InsnData *insn;
    bool hit_in_l1;
    bool hit_in_l2;
    bool hit_in_l3;
    uint64_t victim_tag=-1;


    hwaddr = qemu_plugin_get_hwaddr(info, vaddr);
    if (hwaddr && qemu_plugin_hwaddr_is_io(hwaddr)) {
        return;
    }

    effective_addr = hwaddr ? qemu_plugin_hwaddr_phys_addr(hwaddr) : vaddr;
    cache_idx = vcpu_index % cores;

    g_mutex_lock(&l1_dcache_locks[cache_idx]);
    hit_in_l1 = access_cache(l1_dcaches[cache_idx], effective_addr);
    if (!hit_in_l1) {
        insn = (InsnData *) userdata;
        __atomic_fetch_add(&insn->l1_dmisses, 1, __ATOMIC_SEQ_CST);
        l1_dcaches[cache_idx]->misses++;
    }
    l1_dcaches[cache_idx]->accesses++;
    g_mutex_unlock(&l1_dcache_locks[cache_idx]);

    if (hit_in_l1 || !use_l2) {
        /* No need to access L2 */
        return;
    }

    g_mutex_lock(&l2_ucache_locks[cache_idx]);
    if(use_l3)
    {
	hit_in_l2 = access_cache_return_victim(l2_ucaches[cache_idx], effective_addr,&victim_tag);

    }
    else
    {
        hit_in_l2 = access_cache(l2_ucaches[cache_idx], effective_addr);
    }
    if (!hit_in_l2) {
        insn = (InsnData *) userdata;
        __atomic_fetch_add(&insn->l2_misses, 1, __ATOMIC_SEQ_CST);
        l2_ucaches[cache_idx]->misses++;
    }
    l2_ucaches[cache_idx]->accesses++;
    g_mutex_unlock(&l2_ucache_locks[cache_idx]);
   
    if(hit_in_l2 || !use_l3) return;
     
    //We care about the victims from L2C which will also be 
    //looked up and allocated in l3
    //We do 2 lookups in the l3, the actual miss and then the 
    //victim
    l3_ucaches[cache_idx]->accesses++; //Incrementing access for demand access
    l3_ucaches[cache_idx]->maccesses++; //Incrementing access for demand access
    g_mutex_lock(&l3_ucache_locks[cache_idx]);     
    hit_in_l3 = access_victim_cache(l3_ucaches[cache_idx], effective_addr, false); 
    if (!hit_in_l3) {
        insn = (InsnData *) userdata;
        __atomic_fetch_add(&insn->l3_misses, 1, __ATOMIC_SEQ_CST);
        l3_ucaches[cache_idx]->misses++;
        l3_ucaches[cache_idx]->mmisses++;
    }

    if(victim_tag != -1)//If there was an L2 victim, process that after the original L2 miss
    {
        l3_ucaches[cache_idx]->accesses++;//Incrementing access again for victim access
        l3_ucaches[cache_idx]->vaccesses++;//Incrementing access again for victim access
        hit_in_l3 = access_victim_cache(l3_ucaches[cache_idx], victim_tag, true);  
        if (!hit_in_l3) {
           insn = (InsnData *) userdata;
           __atomic_fetch_add(&insn->l3_misses, 1, __ATOMIC_SEQ_CST);
           l3_ucaches[cache_idx]->misses++;
           l3_ucaches[cache_idx]->vmisses++;
        }
    }

    g_mutex_unlock(&l3_ucache_locks[cache_idx]);

}

static void vcpu_insn_exec(unsigned int vcpu_index, void *userdata)
{
    uint64_t insn_addr;
    InsnData *insn;
    int cache_idx;
    bool hit_in_l1;
    bool hit_in_l2;
    bool hit_in_l3;
    uint64_t victim_tag;

    insn_addr = ((InsnData *) userdata)->addr;

    cache_idx = vcpu_index % cores;
    g_mutex_lock(&l1_icache_locks[cache_idx]);
    hit_in_l1 = access_cache(l1_icaches[cache_idx], insn_addr);
    if (!hit_in_l1) {
        insn = (InsnData *) userdata;
        __atomic_fetch_add(&insn->l1_imisses, 1, __ATOMIC_SEQ_CST);
        l1_icaches[cache_idx]->misses++;
    }
    l1_icaches[cache_idx]->accesses++;
    g_mutex_unlock(&l1_icache_locks[cache_idx]);

    if (hit_in_l1 || !use_l2) {
        /* No need to access L2 */
        return;
    }

    g_mutex_lock(&l2_ucache_locks[cache_idx]);

    if(use_l3)
    {
	hit_in_l2 = access_cache_return_victim(l2_ucaches[cache_idx], insn_addr, &victim_tag);

    }
    else
    {
        hit_in_l2 = access_cache(l2_ucaches[cache_idx], insn_addr);
    }
    if (!hit_in_l2) {
        insn = (InsnData *) userdata;
        __atomic_fetch_add(&insn->l2_misses, 1, __ATOMIC_SEQ_CST);
        l2_ucaches[cache_idx]->imisses++;
        l2_ucaches[cache_idx]->misses++;
    }
    l2_ucaches[cache_idx]->accesses++;
    l2_ucaches[cache_idx]->iaccesses++;
    g_mutex_unlock(&l2_ucache_locks[cache_idx]);

    if(hit_in_l2 || !use_l3) return;
     
    //We care about the victims from L2C which will also be 
    //looked up and allocated in l3
    //We do 2 lookups in the l3, the actual miss and then the 
    //victim
    l3_ucaches[cache_idx]->accesses++;

    g_mutex_lock(&l3_ucache_locks[cache_idx]);     
    hit_in_l3 = access_victim_cache(l3_ucaches[cache_idx], insn_addr, false);  
    if (!hit_in_l3) {
        insn = (InsnData *) userdata;
        __atomic_fetch_add(&insn->l3_misses, 1, __ATOMIC_SEQ_CST);
        l3_ucaches[cache_idx]->misses++;
        l3_ucaches[cache_idx]->mmisses++;
	//For L3, we can probalby count i-side read misses sep but not victims
	//But thats not necessary to counting it as misses, mmisses and vmisses
    }

    if(victim_tag != -1)//If there was an L2 victim, process that after the original L2 miss
    {
        l3_ucaches[cache_idx]->accesses++;//Incrementing access again for victim access
        hit_in_l3 = access_victim_cache(l3_ucaches[cache_idx], victim_tag, true);  
        if (!hit_in_l3) {
           insn = (InsnData *) userdata;
           __atomic_fetch_add(&insn->l3_misses, 1, __ATOMIC_SEQ_CST);
           l3_ucaches[cache_idx]->misses++;
           l3_ucaches[cache_idx]->vmisses++;
        }
    }

    g_mutex_unlock(&l3_ucache_locks[cache_idx]);

}

static void log_interval_stats(void)
{
    if (interval > 0) {
        gzprintf(stats_file, ",\n");
    }
    gzprintf(stats_file, "        {\n");
    gzprintf(stats_file, "            \"index\" : %" PRIu64 ", \"len\" : %" PRIu64 ", \"icount\" : %" PRIu64 ", \"stats\" : {\n",
             interval, cur_insns, total_insns);
    // Not bothering with multi-core summation
    const unsigned i = 0;
    if (use_l3) {
        gzprintf(stats_file, "                \"l3-total\" :      { \"accesses\" : %" PRIu64 ", \"misses\" : %" PRIu64 "},\n",
                 l3_ucaches[i]->accesses, l3_ucaches[i]->misses);
        gzprintf(stats_file, "                \"l3-demandaccesses\" :      { \"accesses\" : %" PRIu64 ", \"misses\" : %" PRIu64 "},\n",
                 l3_ucaches[i]->maccesses, l3_ucaches[i]->mmisses);
        gzprintf(stats_file, "                \"l3-evictionaccesses\" :      { \"accesses\" : %" PRIu64 ", \"misses\" : %" PRIu64 "},\n",
                 l3_ucaches[i]->vaccesses, l3_ucaches[i]->vmisses);
        l3_misses += l3_ucaches[i]->misses;
        l3_accesses += l3_ucaches[i]->accesses;
        l3_mmisses += l3_ucaches[i]->mmisses;
        l3_maccesses += l3_ucaches[i]->maccesses;
        l3_vmisses += l3_ucaches[i]->vmisses;
        l3_vaccesses += l3_ucaches[i]->vaccesses;
        l3_ucaches[i]->mmisses = l3_ucaches[i]->vmisses = l3_ucaches[i]->maccesses = l3_ucaches[i]->vaccesses = l3_ucaches[i]->accesses =l3_ucaches[i]->misses =0;
    }
    if (use_l2) {
        gzprintf(stats_file, "                \"l2-total\" :      { \"accesses\" : %" PRIu64 ", \"misses\" : %" PRIu64 "},\n",
                 l2_ucaches[i]->accesses, l2_ucaches[i]->misses);
        gzprintf(stats_file, "                \"l2-data\" :      { \"accesses\" : %" PRIu64 ", \"misses\" : %" PRIu64 "},\n",
                 (l2_ucaches[i]->accesses - l2_ucaches[i]->iaccesses),(l2_ucaches[i]->misses-l2_ucaches[i]->imisses));
        l2_imisses += l2_ucaches[i]->imisses;
        l2_misses += l2_ucaches[i]->misses;
        l2_iaccesses += l2_ucaches[i]->iaccesses;
        l2_accesses += l2_ucaches[i]->accesses;
        l2_ucaches[i]->misses = l2_ucaches[i]->imisses = l2_ucaches[i]->accesses = l2_ucaches[i]->iaccesses = 0;
    }
    gzprintf(stats_file, "                \"l1-inst\" : "
             "{ \"accesses\" : %" PRIu64 ", \"misses\" : %" PRIu64 "},\n",
             l1_icaches[i]->accesses, l1_icaches[i]->misses);
    l1_imisses += l1_icaches[i]->misses;
    l1_imem_accesses += l1_icaches[i]->accesses;
    l1_icaches[i]->misses = l1_icaches[i]->accesses = 0;
    gzprintf(stats_file, "                \"l1-data\" : "
             "{ \"accesses\" : %" PRIu64 ", \"misses\" : %" PRIu64 "}\n",
             l1_dcaches[i]->accesses, l1_dcaches[i]->misses);
    l1_dmisses += l1_dcaches[i]->misses;
    l1_dmem_accesses += l1_dcaches[i]->accesses;
    l1_dcaches[i]->misses = l1_dcaches[i]->accesses = 0;
    gzprintf(stats_file, "            }\n        }");

    total_insns += cur_insns;
    cur_insns = 0;
    interval++;
}

static void dump_l3_state(Cache* cache)
{
     //Loop through all the L3C lines and dump tags, if not valid dump -1
     for (int set=0; set < cache->num_sets;set++)
     {
	for(int j =0; j < cache->assoc;j++)
        { 		
           if (cache->sets[set].blocks[j].valid)
              gzprintf(dump_file,"PRIu64\n",cache->sets[set].blocks[j].tag);
	   else
              gzprintf(dump_file,"PRIu64\n",-1);
	}
     }
	
}


static void vcpu_tb_exec(unsigned int cpu_index, void *udata)
{
    if (cur_insns + drift < intv_length) {
        return;
    }

    drift = (cur_insns + drift) - intv_length;

    log_interval_stats();
    
    if ((total_insns >= dump_icount) && !dump_done)
    {
	 dump_l3_state(l3_ucaches[0]);
         dump_done = true; 			 
    }
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t n_insns;
    size_t i;
    InsnData *data;

    n_insns = qemu_plugin_tb_n_insns(tb);
    for (i = 0; i < n_insns; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t effective_addr;

        if (sys) {
            effective_addr = (uint64_t) qemu_plugin_insn_haddr(insn);
        } else {
            effective_addr = (uint64_t) qemu_plugin_insn_vaddr(insn);
        }

        /*
         * Instructions might get translated multiple times, we do not create
         * new entries for those instructions. Instead, we fetch the same
         * entry from the hash table and register it for the callback again.
         */
        g_mutex_lock(&hashtable_lock);
        data = g_hash_table_lookup(miss_ht, GUINT_TO_POINTER(effective_addr));
        if (data == NULL) {
            data = g_new0(InsnData, 1);
            data->disas_str = qemu_plugin_insn_disas(insn);
            data->symbol = qemu_plugin_insn_symbol(insn);
            data->addr = effective_addr;
            g_hash_table_insert(miss_ht, GUINT_TO_POINTER(effective_addr),
                               (gpointer) data);
        }
        g_mutex_unlock(&hashtable_lock);

        qemu_plugin_register_vcpu_mem_cb(insn, vcpu_mem_access,
                                         QEMU_PLUGIN_CB_NO_REGS,
                                         rw, data);

        qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec,
                                               QEMU_PLUGIN_CB_NO_REGS, data);
    }

    if (stats_file != Z_NULL) {
        qemu_plugin_register_vcpu_tb_exec_cb(tb, vcpu_tb_exec,
                                             QEMU_PLUGIN_CB_NO_REGS,
                                             (void *)n_insns);
        qemu_plugin_register_vcpu_tb_exec_inline(tb, QEMU_PLUGIN_INLINE_ADD_U64,
                                                 &cur_insns, n_insns);
    }
}

static void insn_free(gpointer data)
{
    InsnData *insn = (InsnData *) data;
    g_free(insn->disas_str);
    g_free(insn);
}

static void cache_free(Cache *cache)
{
    for (int i = 0; i < cache->num_sets; i++) {
        g_free(cache->sets[i].blocks);
    }

    if (metadata_destroy) {
        metadata_destroy(cache);
    }

    g_free(cache->sets);
    g_free(cache);
}

static void caches_free(Cache **caches)
{
    int i;

    for (i = 0; i < cores; i++) {
        cache_free(caches[i]);
    }
}

static void append_stats_line(GString *line, uint64_t l1_daccess,
                              uint64_t l1_dmisses, uint64_t l1_iaccess,
                              uint64_t l1_imisses,  uint64_t l2_access,
                              uint64_t l2_misses, uint64_t l2_daccess,
                              uint64_t l2_dmisses,uint64_t l2_evictions,uint64_t l3_access,
			      uint64_t l3_misses, uint64_t l3_daccess, uint64_t l3_mmisses, 
			      uint64_t l3_vmisses, uint64_t l3_evictions)
{
    double l1_dmiss_rate, l1_imiss_rate, l2_miss_rate, l3_miss_rate;

    l1_dmiss_rate = ((double) l1_dmisses) / (l1_daccess) * 100.0;
    l1_imiss_rate = ((double) l1_imisses) / (l1_iaccess) * 100.0;

    g_string_append_printf(line, "%-14lu %-12lu %9.4lf%%  %-14lu %-12lu"
                           " %9.4lf%%",
                           l1_daccess,
                           l1_dmisses,
                           l1_daccess ? l1_dmiss_rate : 0.0,
                           l1_iaccess,
                           l1_imisses,
                           l1_iaccess ? l1_imiss_rate : 0.0);

    if (use_l2) {
        l2_miss_rate =  ((double) l2_misses) / (l2_access) * 100.0;
        g_string_append_printf(line, "  %-12lu %-11lu %-11lu %-11lu %-11lu %10.4lf%%",
                               l2_access,
                               l2_misses,l2_daccess, l2_dmisses, l2_evictions,
                               l2_access ? l2_miss_rate : 0.0);
    }
    if (use_l3) {
        l3_miss_rate =  ((double) l3_misses) / (l3_access) * 100.0;
        g_string_append_printf(line, "  %-12lu %-11lu %-11lu %-11lu %-11lu %-11lu %10.4lf%%",
                               l3_access,
                               l3_misses,l3_mmisses,l3_daccess,l3_vmisses,l3_evictions,
                               l3_access ? l3_miss_rate : 0.0);
    }

    g_string_append(line, "\n");
}

static void sum_stats(void)
{
    int i;

    g_assert(cores > 1);
    for (i = 0; i < cores; i++) {
        l1_imisses += l1_icaches[i]->misses;
        l1_dmisses += l1_dcaches[i]->misses;
        l1_imem_accesses += l1_icaches[i]->accesses;
        l1_dmem_accesses += l1_dcaches[i]->accesses;

        if (use_l2) {
            l2_imisses += l2_ucaches[i]->imisses;
            l2_dmisses += l2_ucaches[i]->misses;
            l2_imem_accesses += l2_ucaches[i]->iaccesses;
            l2_dmem_accesses += l2_ucaches[i]->accesses;
        }
    }
}

static int dcmp(gconstpointer a, gconstpointer b)
{
    InsnData *insn_a = (InsnData *) a;
    InsnData *insn_b = (InsnData *) b;

    return insn_a->l1_dmisses < insn_b->l1_dmisses ? 1 : -1;
}

static int icmp(gconstpointer a, gconstpointer b)
{
    InsnData *insn_a = (InsnData *) a;
    InsnData *insn_b = (InsnData *) b;

    return insn_a->l1_imisses < insn_b->l1_imisses ? 1 : -1;
}

static int l2_cmp(gconstpointer a, gconstpointer b)
{
    InsnData *insn_a = (InsnData *) a;
    InsnData *insn_b = (InsnData *) b;

    return insn_a->l2_misses < insn_b->l2_misses ? 1 : -1;
}

static void log_stats(void)
{
    int i;
    Cache *icache, *dcache, *l2_cache, *l3_cache;

    g_autoptr(GString) rep = g_string_new("l1icache size, l1dcache size, l2 size, l3 size");
    g_string_append(rep, "\n");
    g_string_append_printf(rep,"%-11u %-11u %-11u %-11u",l1_icaches[0]->cachesize, l1_dcaches[0]->cachesize, l2_ucaches[0]->cachesize, l3_ucaches[0]->cachesize); 
    g_string_append(rep, "\n");
    g_string_append(rep, "core #, data accesses, data misses,"
                                          " dmiss rate, insn accesses,"
                                          " insn misses, imiss rate");

    if (use_l2) {
        g_string_append(rep, ", l2 Taccesses, l2 Tmisses, l2 daccesses, l2 dmisses, l2 evictions, l2 miss rate");
    }
    if (use_l3) {
        g_string_append(rep, ", l3 Taccesses, l3 Tmisses, l2 daccesses, l3 dmmisses, l3 dvmisses, l3 evictions, l3 miss rate");
    }

    g_string_append(rep, "\n");

    for (i = 0; i < cores; i++) {
        g_string_append_printf(rep, "%-8d", i);
        dcache = l1_dcaches[i];
        icache = l1_icaches[i];
        l2_cache = use_l2 ? l2_ucaches[i] : NULL;
        l3_cache = use_l3 ? l3_ucaches[i] : NULL;
        append_stats_line(rep, dcache->accesses, dcache->misses,
                icache->accesses, icache->misses,
                l2_cache ? (l2_cache->accesses+l2_cache->iaccesses) : 0,
                l2_cache ? (l2_cache->misses+l2_cache->imisses) : 0,
                l2_cache ? (l2_cache->accesses) : 0,
                l2_cache ? (l2_cache->misses) : 0,
                l2_cache ? (l2_cache->evictions) : 0,
                l3_cache ? (l3_cache->accesses+l3_cache->iaccesses) : 0,
                l3_cache ? (l3_cache->misses+l3_cache->imisses) : 0,
                l3_cache ? (l3_cache->accesses) : 0,
                l3_cache ? (l3_cache->mmisses) : 0,
                l3_cache ? (l3_cache->vmisses) : 0,
                l3_cache ? (l3_cache->evictions) : 0
		);
    }

    if (cores > 1) {
        sum_stats();
        g_string_append_printf(rep, "%-8s", "sum");
        append_stats_line(rep, l1_dmem_accesses, l1_dmisses,
                l1_imem_accesses, l1_imisses,
                l2_cache ? (l2_cache->accesses+l2_cache->iaccesses) : 0,
                l2_cache ? (l2_cache->misses+l2_cache->imisses) : 0,
                l2_cache ? (l2_cache->accesses) : 0,
                l2_cache ? (l2_cache->misses) : 0,
                l2_cache ? (l2_cache->evictions) : 0,
                l3_cache ? (l3_cache->accesses+l3_cache->iaccesses) : 0,
                l3_cache ? (l3_cache->misses+l3_cache->imisses) : 0,
                l3_cache ? (l3_cache->accesses) : 0,
                l3_cache ? (l3_cache->mmisses) : 0,
                l3_cache ? (l3_cache->vmisses) : 0,
                l3_cache ? (l3_cache->evictions) : 0
		);
    }

    g_string_append(rep, "\n");
    qemu_plugin_outs(rep->str);
}

static void log_top_insns(void)
{
    int i;
    GList *curr, *miss_insns;
    InsnData *insn;

    miss_insns = g_hash_table_get_values(miss_ht);
    miss_insns = g_list_sort(miss_insns, dcmp);
    g_autoptr(GString) rep = g_string_new("");
    g_string_append_printf(rep, "%s", "address, data misses, instruction\n");

    for (curr = miss_insns, i = 0; curr && i < limit; i++, curr = curr->next) {
        insn = (InsnData *) curr->data;
        g_string_append_printf(rep, "0x%" PRIx64, insn->addr);
        if (insn->symbol) {
            g_string_append_printf(rep, " (%s)", insn->symbol);
        }
        g_string_append_printf(rep, ", %ld, %s\n", insn->l1_dmisses,
                               insn->disas_str);
    }

    miss_insns = g_list_sort(miss_insns, icmp);
    g_string_append_printf(rep, "%s", "\naddress, fetch misses, instruction\n");

    for (curr = miss_insns, i = 0; curr && i < limit; i++, curr = curr->next) {
        insn = (InsnData *) curr->data;
        g_string_append_printf(rep, "0x%" PRIx64, insn->addr);
        if (insn->symbol) {
            g_string_append_printf(rep, " (%s)", insn->symbol);
        }
        g_string_append_printf(rep, ", %ld, %s\n", insn->l1_imisses,
                               insn->disas_str);
    }

    if (!use_l2) {
        goto finish;
    }

    miss_insns = g_list_sort(miss_insns, l2_cmp);
    g_string_append_printf(rep, "%s", "\naddress, L2 misses, instruction\n");

    for (curr = miss_insns, i = 0; curr && i < limit; i++, curr = curr->next) {
        insn = (InsnData *) curr->data;
        g_string_append_printf(rep, "0x%" PRIx64, insn->addr);
        if (insn->symbol) {
            g_string_append_printf(rep, " (%s)", insn->symbol);
        }
        g_string_append_printf(rep, ", %ld, %s\n", insn->l2_misses,
                               insn->disas_str);
    }

finish:
    if (stats_file == Z_NULL) {
        qemu_plugin_outs(rep->str);
    }
    g_list_free(miss_insns);
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    if (stats_file == Z_NULL) {
        log_stats();
        log_top_insns();
    } else {
        log_interval_stats();
        gzprintf(stats_file, "\n    ],\n    \"instructions\" : %" PRIu64 ",\n    \"stats\" : {\n", total_insns);
        if (use_l3) {
            gzprintf(stats_file, "                \"l3-total\" :      { \"accesses\" : %" PRIu64 ", \"misses\" : %" PRIu64 "},\n",
                     l3_accesses, l3_misses);
            gzprintf(stats_file, "                \"l3-demandaccesses\" :      { \"accesses\" : %" PRIu64 ", \"misses\" : %" PRIu64 "},\n",
                     l3_maccesses, l3_mmisses);
            gzprintf(stats_file, "                \"l3-evictionaccesses\" :      { \"accesses\" : %" PRIu64 ", \"misses\" : %" PRIu64 "},\n",
                     l3_vaccesses, l3_vmisses);
        }
        if (use_l2) {
            gzprintf(stats_file, "                \"l2-total\" :      { \"accesses\" : %" PRIu64 ", \"misses\" : %" PRIu64 "},\n",
                     l2_accesses, l2_misses);
            gzprintf(stats_file, "                \"l2-data\" :      { \"accesses\" : %" PRIu64 ", \"misses\" : %" PRIu64 "},\n",
                     (l2_accesses - l2_iaccesses), (l2_misses - l2_imisses));
        }
        gzprintf(stats_file, "                \"l1-inst\" : "
                 "{ \"accesses\" : %" PRIu64 ", \"misses\" : %" PRIu64 "},\n", l1_imem_accesses, l1_imisses);
        gzprintf(stats_file, "                \"l1-data\" : "
                 "{ \"accesses\" : %" PRIu64 ", \"misses\" : %" PRIu64 "}\n", l1_dmem_accesses, l1_dmisses);
        gzprintf(stats_file, "    }\n}\n");
        gzclose_w(stats_file);
    }

    caches_free(l1_dcaches);
    caches_free(l1_icaches);

    g_free(l1_dcache_locks);
    g_free(l1_icache_locks);

    if (use_l2) {
        caches_free(l2_ucaches);
        g_free(l2_ucache_locks);
    }
    if (use_l3) {
        caches_free(l3_ucaches);
        g_free(l3_ucache_locks);
    }

    g_hash_table_destroy(miss_ht);
}

static void policy_init(void)
{
    switch (policy) {
    case LRU:
        update_hit = lru_update_blk;
        update_miss = lru_update_blk;
        metadata_init = lru_priorities_init;
        metadata_destroy = lru_priorities_destroy;
        break;
    case FIFO:
        update_miss = fifo_update_on_miss;
        metadata_init = fifo_init;
        metadata_destroy = fifo_destroy;
        break;
    case RAND:
        rng = g_rand_new();
        break;
    default:
        g_assert_not_reached();
    }
}

static const char *policy_string(enum EvictionPolicy p)
{
    switch (p) {
    default:
    case LRU: return "LRU";
    case RAND: return "RAND";
    case FIFO: return "FIFO";
    }
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    int i;
    int l1_iassoc, l1_iblksize, l1_icachesize;
    int l1_dassoc, l1_dblksize, l1_dcachesize;
    int l2_assoc, l2_blksize, l2_cachesize;
    int l3_assoc, l3_blksize, l3_cachesize;

    limit = 32;
    sys = info->system_emulation;

    l1_dassoc = 8;
    l1_dblksize = 64;
    l1_dcachesize = l1_dblksize * l1_dassoc * 32;

    l1_iassoc = 8;
    l1_iblksize = 64;
    l1_icachesize = l1_iblksize * l1_iassoc * 32;

    l2_assoc = 16;
    l2_blksize = 64;
    l2_cachesize = l2_assoc * l2_blksize * 2048;

    l3_assoc = 16;
    l3_blksize = 64;
    l3_cachesize = l3_assoc * l3_blksize * 16384;//Defaults to 64MB

    policy = LRU;

    cores = sys ? qemu_plugin_n_vcpus() : 1;

    for (i = 0; i < argc; i++) {
        char *opt = argv[i];
        g_autofree char **tokens = g_strsplit(opt, "=", 2);

        if (g_strcmp0(tokens[0], "iblksize") == 0) {
            l1_iblksize = STRTOLL(tokens[1]);
        } else if (g_strcmp0(tokens[0], "iassoc") == 0) {
            l1_iassoc = STRTOLL(tokens[1]);
        } else if (g_strcmp0(tokens[0], "icachesize") == 0) {
            l1_icachesize = STRTOLL(tokens[1]);
        } else if (g_strcmp0(tokens[0], "dblksize") == 0) {
            l1_dblksize = STRTOLL(tokens[1]);
        } else if (g_strcmp0(tokens[0], "dassoc") == 0) {
            l1_dassoc = STRTOLL(tokens[1]);
        } else if (g_strcmp0(tokens[0], "dcachesize") == 0) {
            l1_dcachesize = STRTOLL(tokens[1]);
        } else if (g_strcmp0(tokens[0], "limit") == 0) {
            limit = STRTOLL(tokens[1]);
        } else if (g_strcmp0(tokens[0], "cores") == 0) {
            cores = STRTOLL(tokens[1]);
        } else if (g_strcmp0(tokens[0], "l3cachesize") == 0) {
            use_l3 = true;
            l3_cachesize = STRTOLL(tokens[1]);
        } else if (g_strcmp0(tokens[0], "l3blksize") == 0) {
            use_l3 = true;
            l3_blksize = STRTOLL(tokens[1]);
        } else if (g_strcmp0(tokens[0], "l3assoc") == 0) {
            use_l3 = true;
            l3_assoc = STRTOLL(tokens[1]);
        } else if (g_strcmp0(tokens[0], "l3") == 0) {
            if (!qemu_plugin_bool_parse(tokens[0], tokens[1], &use_l3)) {
                fprintf(stderr, "boolean argument parsing failed: %s\n", opt);
                return -1;
            }
        } else if (g_strcmp0(tokens[0], "l2cachesize") == 0) {
            use_l2 = true;
            l2_cachesize = STRTOLL(tokens[1]);
        } else if (g_strcmp0(tokens[0], "l2blksize") == 0) {
            use_l2 = true;
            l2_blksize = STRTOLL(tokens[1]);
        } else if (g_strcmp0(tokens[0], "l2assoc") == 0) {
            use_l2 = true;
            l2_assoc = STRTOLL(tokens[1]);
        } else if (g_strcmp0(tokens[0], "l2") == 0) {
            if (!qemu_plugin_bool_parse(tokens[0], tokens[1], &use_l2)) {
                fprintf(stderr, "boolean argument parsing failed: %s\n", opt);
                return -1;
            }
        } else if (g_strcmp0(tokens[0], "evict") == 0) {
            if (g_strcmp0(tokens[1], "rand") == 0) {
                policy = RAND;
            } else if (g_strcmp0(tokens[1], "lru") == 0) {
                policy = LRU;
            } else if (g_strcmp0(tokens[1], "fifo") == 0) {
                policy = FIFO;
            } else {
                fprintf(stderr, "invalid eviction policy: %s\n", opt);
                return -1;
            }
        } else if (g_strcmp0(tokens[0], "stats") == 0) {
            stats_file = gzopen(tokens[1], "wb9");
            if (stats_file == Z_NULL) {
                return -1;
            }
        } else if (g_strcmp0(tokens[0], "ilen") == 0) {
            intv_length = strtoull(tokens[1], NULL, 0);
        } else if (g_strcmp0(tokens[0], "l3_dump_icount") == 0) {
            dump_icount = strtoull(tokens[1], NULL, 0);
        } else if (g_strcmp0(tokens[0], "l3_dump_file") == 0) {
            dump_file = gzopen(tokens[1], "wb9");
            if (dump_file == Z_NULL) {
                return -1;
            }

        } else {
            fprintf(stderr, "option parsing failed: %s\n", opt);
            return -1;
        }
    }

    policy_init();

    l1_dcaches = caches_init(l1_dblksize, l1_dassoc, l1_dcachesize);
    if (!l1_dcaches) {
        const char *err = cache_config_error(l1_dblksize, l1_dassoc, l1_dcachesize);
        fprintf(stderr, "dcache cannot be constructed from given parameters\n");
        fprintf(stderr, "%s\n", err);
        return -1;
    }

    l1_icaches = caches_init(l1_iblksize, l1_iassoc, l1_icachesize);
    if (!l1_icaches) {
        const char *err = cache_config_error(l1_iblksize, l1_iassoc, l1_icachesize);
        fprintf(stderr, "icache cannot be constructed from given parameters\n");
        fprintf(stderr, "%s\n", err);
        return -1;
    }

    l2_ucaches = use_l2 ? caches_init(l2_blksize, l2_assoc, l2_cachesize) : NULL;
    if (!l2_ucaches && use_l2) {
        const char *err = cache_config_error(l2_blksize, l2_assoc, l2_cachesize);
        fprintf(stderr, "L2 cache cannot be constructed from given parameters\n");
        fprintf(stderr, "%s\n", err);
        return -1;
    }

    l3_ucaches = use_l3 ? caches_init(l3_blksize, l3_assoc, l3_cachesize) : NULL;
    if (!l3_ucaches && use_l3) {
        const char *err = cache_config_error(l3_blksize, l3_assoc, l3_cachesize);
        fprintf(stderr, "L3 cache cannot be constructed from given parameters\n");
        fprintf(stderr, "%s\n", err);
        return -1;
    }

    l1_dcache_locks = g_new0(GMutex, cores);
    l1_icache_locks = g_new0(GMutex, cores);
    l2_ucache_locks = use_l2 ? g_new0(GMutex, cores) : NULL;
    l3_ucache_locks = use_l3 ? g_new0(GMutex, cores) : NULL;

    if (stats_file != Z_NULL) {
        if (cores > 1) {
            fprintf(stderr, "Cache \"stats\" mode only supports a single core\n");
            return -1;
        }
        gzprintf(stats_file, "{\n    \"config\" : {\n        \"policy\" : \"%s\",\n", policy_string(policy));
        if (use_l2) {
            gzprintf(stats_file, "        \"l2\" :          { \"assoc\": %u, \"blksize\": %u, \"size\": %u},\n",
                     l2_assoc, l2_blksize, l2_cachesize);
        }
        if (use_l3) {
            gzprintf(stats_file, "        \"l3\" :          { \"assoc\": %u, \"blksize\": %u, \"size\": %u},\n",
                     l3_assoc, l3_blksize, l3_cachesize);
        }
            gzprintf(stats_file, "        \"l1-inst\" :     { \"assoc\": %u, \"blksize\": %u, \"size\": %u},\n",
                     l1_iassoc, l1_iblksize, l1_icachesize);
            gzprintf(stats_file, "        \"l1-data\" :     { \"assoc\": %u, \"blksize\": %u, \"size\": %u}\n",
                     l1_dassoc, l1_dblksize, l1_dcachesize);
        gzprintf(stats_file, "    },\n    \"intervals\": [\n");
    }

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

    miss_ht = g_hash_table_new_full(NULL, g_direct_equal, NULL, insn_free);

    return 0;
}
