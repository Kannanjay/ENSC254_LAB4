#include "cache.h"
#include "dogfault.h"
#include <assert.h>
#include <ctype.h>
#include <getopt.h>
#include <math.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// DO NOT MODIFY THIS FILE. INVOKE AFTER EACH ACCESS FROM runTrace
void print_result(result r)
{
  if (r.status == CACHE_EVICT)
    printf(" [status: miss eviction, victim_block: 0x%llx, insert_block: 0x%llx]",
           r.victim_block_addr, r.insert_block_addr);
  if (r.status == CACHE_HIT)
    printf(" [status: hit]");
  if (r.status == CACHE_MISS)
    printf(" [status: miss, insert_block: 0x%llx]", r.insert_block_addr);
}

/* This is the entry point to operate the cache for a given address in the trace file.
 * First, is increments the global lru_clock in the corresponding cache set for the address.
 * Second, it checks if the address is already in the cache using the "probe_cache" function.
 * If yes, it is a cache hit:
 *     1) call the "hit_cacheline" function to update the counters inside the hit cache
 *        line, including its lru_clock and access_counter.
 *     2) record a hit status in the return "result" struct and update hit_count
 * Otherwise, it is a cache miss:
 *     1) call the "insert_cacheline" function, trying to find an empty cache line in the
 *        cache set and insert the address into the empty line.
 *     2) if the "insert_cacheline" function returns true, record a miss status and the
          inserted block address in the return "result" struct and update miss_count
 *     3) otherwise, if the "insert_cacheline" function returns false:
 *          a) call the "victim_cacheline" function to figure which victim cache line to
 *             replace based on the cache replacement policy (LRU and LFU).
 *          b) call the "replace_cacheline" function to replace the victim cache line with
 *             the new cache line to insert.
 *          c) record an eviction status, the victim block address, and the inserted block
 *             address in the return "result" struct. Update miss_count and eviction_count.
 */
result operateCache(const unsigned long long address, Cache *cache)
{
  result r;
  unsigned long long block_addr = address_to_block(address, cache->blockBits); // Calculate the block address
  int set_index = cache_set(address, cache->setBits);                          // Determine the set index

  Set *set = &cache->sets[set_index]; // Get the corresponding cache set
  set->lru_clock++;                   // Increment the global LRU clock

  if (probe_cache(block_addr, cache))
  {
    // Cache hit
    hit_cacheline(block_addr, cache);
    cache->hit_count++;
    r.status = CACHE_HIT;
  }
  else
  {
    // Cache miss
    cache->miss_count++;
    if (insert_cacheline(block_addr, cache))
    {
      // Inserted into an empty cache line
      r.status = CACHE_MISS;
      r.insert_block_addr = block_addr;
    }
    else
    {
      // No empty cache line, eviction needed
      unsigned long long victim_block_addr = victim_cacheline(address, cache);
      replace_cacheline(victim_block_addr, address, cache);
      cache->eviction_count++;
      r.status = CACHE_EVICT;
      r.victim_block_addr = victim_block_addr;
      r.insert_block_addr = block_addr;
    }
  }

  return r;
}

// HELPER FUNCTIONS USEFUL FOR IMPLEMENTING THE CACHE
// Given an address, return the block (aligned) address,
// i.e., byte offset bits are cleared to 0
unsigned long long address_to_block(const unsigned long long address, const Cache *cache)
{
  /* YOUR CODE HERE */
  int blockBits = cache->blockBits;                          // number of block offset bits
  unsigned long long blockMask = ~((1ULL << blockBits) - 1); // clear the block offset bits to get the block address
  return address & blockMask;
}

// Return the cache tag of an address
unsigned long long cache_tag(const unsigned long long address, const Cache *cache)
{
  /* YOUR CODE HERE */
  int blockBits = cache->blockBits;
  int setBits = cache->setBits;
  int shiftBits = blockBits + setBits;
  return address >> shiftBits;
}

// Return the cache set index of the address
unsigned long long cache_set(const unsigned long long address, const Cache *cache)
{
  /* YOUR CODE HERE */
  int blockBits = cache->blockBits;

  int setBits = cache->setBits;

  unsigned long long setMask = (1ULL << setBits) - 1;

  return (address > blockBits) & setMask;
}

// Check if the address is found in the cache. If so, return true. else return false.
bool probe_cache(const unsigned long long address, const Cache *cache)
{
  /* YOUR CODE HERE */
  unsigned long long block_addr = address_to_block(address, cache); // to calculate the block address
  int set_index = cache_set(address, cache);                        // calculate set index
  unsigned long long tag = cache_tag(address, cache);

  Set *set = &cache->sets[set_index]; // obtain the cache set

  // Loop over the lines in the set to find the tag
  for (int i = 0; i < cache->linesPerSet; i++)
  {
    Line *line = &set->lines[i];
    if (line->valid && line->tag == tag)
    {
      return true;
    }
  }
  return false;
}

// Access address in cache. Called only if probe is successful.
// Update the LRU (least recently used) or LFU (least frequently used) counters.
void hit_cacheline(const unsigned long long address, Cache *cache)
{
  // Calculate the block address
  unsigned long long block_addr = address_to_block(address, cache);

  // Calculate the set index
  int set_index = cache_set(address, cache);

  // Extract the tag
  unsigned long long tag = cache_tag(address, cache);

  // Get the cache set
  Set *set = &cache->sets[set_index];

  // Iterate over the lines in the set to find the matching cache line
  for (int i = 0; i < cache->linesPerSet; i++)
  {
    Line *line = &set->lines[i];
    if (line->valid && line->tag == tag)
    {
      // Update the LRU or LFU counters
      if (cache->lfu == 0)
      {
        // LRU: Update the LRU clock for the accessed line
        line->lru_clock = set->lru_clock;
      }
      else
      {
        // LFU: Increment the access counter for the accessed line
        line->access_counter++;
      }
      break;
    }
  }
}

/* This function is only called if probe_cache returns false, i.e., the address is
 * not in the cache. In this function, it will try to find an empty (i.e., invalid)
 * cache line for the address to insert.
 * If it found an empty one:
 *     1) it inserts the address into that cache line (marking it valid).
 *     2) it updates the cache line's lru_clock based on the global lru_clock
 *        in the cache set and initiates the cache line's access_counter.
 *     3) it returns true.
 * Otherwise, it returns false.
 */
bool insert_cacheline(const unsigned long long address, Cache *cache)
{
  /* YOUR CODE HERE */
  unsigned long long block_addr = address_to_block(address, cache);

  int set_index = cache_set(address, cache);

  Set *set = &cache->sets[set_index];
  unsigned long long tag = cache_tag(address, cache);

  for (int i = 0; i < cache->linesPerSet; i++)
  {
    Line *line = &set->lines[i];
    if (!line->valid)
    {
      line->block_addr = block_addr;
      line->tag = tag;
      line->valid = true;
      line->lru_clock = set->lru_clock;
      line->access_counter = 1;
      return true;
    }
  }

  // No empty cache line found
  return false;
}

// If there is no empty cacheline, this method figures out which cacheline to replace
// depending on the cache replacement policy (LRU and LFU). It returns the block address
// of the victim cacheline; note we no longer have access to the full address of the victim
unsigned long long victim_cacheline(const unsigned long long address,
                                    const Cache *cache)
{
  /* YOUR CODE HERE */
  int set_index = cache_set(address, cache);

  Set *set = &cache->sets[set_index];
  int victim_index = -1;
  unsigned long long victim_block_addr = 0;
  // LRU policy
  if (cache->lfu == 0)
  {
    unsigned long long min_lru_clock = ~0ULL; // max possible number
    for (int i = 0; i < cache->linesPerSet; i++)
    {
      Line *line = &set->lines[i];
      if (line->lru_clock < min_lru_clock)
      {
        min_lru_clock = line->lru_clock;
        victim_index = i;
      }
    }
  }
  else
  {
    int min_access_counter = ~0;
    unsigned long long min_lru_clock = ~0ULL;
    for (int i = 0; i < cache->linesPerSet; i++)
    {
      Line *line = &set->lines[i];
      if (line->access_counter < min_access_counter || line->access_counter == min_access_counter && line->lru_clock < min_lru_clock)
      {
        min_access_counter = line->access_counter;
        min_lru_clock = line->lru_clock;
        victim_index = -1;
      }
    }
  }
  if (victim_index != -1)
  {
    victim_block_addr = set->lines[victim_index].block_addr;
  }
  return victim_block_addr;
}

/* Replace the victim cacheline with the new address to insert. Note for the victim cachline,
 * we only have its block address. For the new address to be inserted, we have its full address.
 * Remember to update the new cache line's lru_clock based on the global lru_clock in the cache
 * set and initiate the cache line's access_counter.
 */
void replace_cacheline(const unsigned long long victim_block_addr, const unsigned long long insert_addr, Cache *cache)
{
  /* YOUR CODE HERE */
  int set_index = cache_set(insert_addr, cache);
  unsigned long long new_tag = cache_tag(insert_addr, cache);

  Set *set = &cache->sets[set_index];

  for (int i = 0; i < cache->linesPerSet; i++)
  {
    Line *line = &set->lines[i];
    if (line->block_addr == victim_block_addr)
    {
      line->block_addr == address_to_block(insert_addr, cache);
      line->tag = new_tag;
      line->valid = true;
      line->lru_clock = set->lru_clock;
      line->access_counter = 1;
      break;
    }
  }
}

// allocate the memory space for the cache with the given cache parameters
// and initialize the cache sets and lines.
// Initialize the cache name to the given name
void cacheSetUp(Cache *cache, char *name)
{
  // Initialize the cache name
  cache->name = (char *)malloc(strlen(name) + 1);
  strcpy(cache->name, name);

  // Calculate the number of sets
  int numSets = 1 << cache->setBits; // 2^setBits

  // Allocate memory for the array of sets
  cache->sets = (Set *)malloc(numSets * sizeof(Set));

  // Allocate memory for each set's lines
  for (int i = 0; i < numSets; i++)
  {
    cache->sets[i].lines = (Line *)malloc(cache->linesPerSet * sizeof(Line));
    cache->sets[i].lru_clock = 0; // Initialize the global lru_clock for the set

    // Initialize each cache line in the set
    for (int j = 0; j < cache->linesPerSet; j++)
    {
      cache->sets[i].lines[j].valid = false;
      cache->sets[i].lines[j].tag = 0;
      cache->sets[i].lines[j].lru_clock = 0;
      cache->sets[i].lines[j].access_counter = 0;
    }
  }
}

// deallocate the memory space for the cache
void deallocate(Cache *cache)
{
  /* YOUR CODE HERE */

  int numSets = 1 << cache->setBits; // 2^setBits

  // Free the memory for each set's lines
  for (int i = 0; i < numSets; i++)
  {
    free(cache->sets[i].lines);
  }

  // Free the memory for the sets array
  free(cache->sets);

  // Free the memory for the cache name
  free(cache->name);
}

// print out summary stats for the cache
void printSummary(const Cache *cache)
{
  printf("%s hits: %d, misses: %d, evictions: %d\n", cache->name, cache->hit_count,
         cache->miss_count, cache->eviction_count);
}
