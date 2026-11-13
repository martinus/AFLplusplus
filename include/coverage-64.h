/*
   american fuzzy lop++ - part of the AFL++ project
   ------------------------------------------------

   Copyright 2019-2026 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may obtain a copy at https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#ifndef _COVERAGE_H

#define _COVERAGE_H

#include "config.h"
#include "types.h"

#define _AFL_INTSIZEVAR u64

#if (defined(__AVX512F__) && defined(__AVX512DQ__)) || defined(__AVX2__)
  #include <immintrin.h>
#endif

u32 skim(const u64 *virgin, const u64 *current, const u64 *current_end);
u64 classify_word(u64 word);

inline u64 classify_word(u64 word) {

  u16 mem16[4];
  memcpy(mem16, &word, sizeof(mem16));

  mem16[0] = count_class_lookup16[mem16[0]];
  mem16[1] = count_class_lookup16[mem16[1]];
  mem16[2] = count_class_lookup16[mem16[2]];
  mem16[3] = count_class_lookup16[mem16[3]];

  memcpy(&word, mem16, sizeof(mem16));
  return word;

}

void simplify_trace(afl_state_t *afl, u8 *bytes) {

  u64 *mem = (u64 *)bytes;
  u32  i = (afl->fsrv.map_size >> 3);

  /* This writes to all bytes, also to those that are 0. */
  if (bytes == afl->fsrv.trace_bits) { afl_fsrv_map_summary_stale(&afl->fsrv); }

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) {

      u8 *mem8 = (u8 *)mem;

      mem8[0] = simplify_lookup[mem8[0]];
      mem8[1] = simplify_lookup[mem8[1]];
      mem8[2] = simplify_lookup[mem8[2]];
      mem8[3] = simplify_lookup[mem8[3]];
      mem8[4] = simplify_lookup[mem8[4]];
      mem8[5] = simplify_lookup[mem8[5]];
      mem8[6] = simplify_lookup[mem8[6]];
      mem8[7] = simplify_lookup[mem8[7]];

    } else

      *mem = 0x0101010101010101ULL;

    mem++;

  }

}

inline void classify_counts(afl_forkserver_t *fsrv) {

  u64 *mem = (u64 *)fsrv->trace_bits;
  u32  i = (fsrv->map_size >> 3);

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) { *mem = classify_word(*mem); }

    mem++;

  }

}

/* Updates the virgin bits, then reflects whether a new count or a new tuple is
 * seen in ret. */
inline void discover_word(u8 *ret, u64 *current, u64 *virgin) {

  /* Optimize for (*current & *virgin) == 0 - i.e., no bits in current bitmap
     that have not been already cleared from the virgin map - since this will
     almost always be the case. */

  if (*current & *virgin) {

    if (likely(*ret < 2)) {

      u8 *cur = (u8 *)current;
      u8 *vir = (u8 *)virgin;

      /* Looks like we have not found any new bytes yet; see if any non-zero
         bytes in current[] are pristine in virgin[]. */

      if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
          (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff) ||
          (cur[4] && vir[4] == 0xff) || (cur[5] && vir[5] == 0xff) ||
          (cur[6] && vir[6] == 0xff) || (cur[7] && vir[7] == 0xff))
        *ret = 2;
      else
        *ret = 1;

    }

    *virgin &= ~*current;

  }

}

#if defined(__AVX512F__) && defined(__AVX512DQ__)
  #define PACK_SIZE 64
inline u32 skim(const u64 *virgin, const u64 *current, const u64 *current_end) {

  for (; current != current_end; virgin += 8, current += 8) {

    __m512i  value = *(__m512i *)current;
    __mmask8 mask = _mm512_testn_epi64_mask(value, value);

    /* All bytes are zero. */
    if (likely(mask == 0xff)) continue;

        /* Look for nonzero bytes and check for new bits. */
  #define UNROLL(x)                                                            \
    if (unlikely(!(mask & (1 << x)) && classify_word(current[x]) & virgin[x])) \
    return 1
    UNROLL(0);
    UNROLL(1);
    UNROLL(2);
    UNROLL(3);
    UNROLL(4);
    UNROLL(5);
    UNROLL(6);
    UNROLL(7);
  #undef UNROLL

  }

  return 0;

}

#endif

#if !defined(PACK_SIZE) && defined(__AVX2__)
  #define PACK_SIZE 32
inline u32 skim(const u64 *virgin, const u64 *current, const u64 *current_end) {

  __m256i zeroes = _mm256_setzero_si256();

  for (; current < current_end; virgin += 4, current += 4) {

    __m256i value = *(__m256i *)current;
    __m256i cmp = _mm256_cmpeq_epi64(value, zeroes);
    u32     mask = _mm256_movemask_epi8(cmp);

    /* All bytes are zero. */
    if (likely(mask == (u32)-1)) continue;

    /* Look for nonzero bytes and check for new bits. */
    if (unlikely(!(mask & 0xff) && classify_word(current[0]) & virgin[0]))
      return 1;
    if (unlikely(!(mask & 0xff00) && classify_word(current[1]) & virgin[1]))
      return 1;
    if (unlikely(!(mask & 0xff0000) && classify_word(current[2]) & virgin[2]))
      return 1;
    if (unlikely(!(mask & 0xff000000) && classify_word(current[3]) & virgin[3]))
      return 1;

  }

  return 0;

}

#endif

#if !defined(PACK_SIZE)
  #define PACK_SIZE 32
inline u32 skim(const u64 *virgin, const u64 *current, const u64 *current_end) {

  for (; current < current_end; virgin += 4, current += 4) {

    if (unlikely(current[0] && classify_word(current[0]) & virgin[0])) return 1;
    if (unlikely(current[1] && classify_word(current[1]) & virgin[1])) return 1;
    if (unlikely(current[2] && classify_word(current[2]) & virgin[2])) return 1;
    if (unlikely(current[3] && classify_word(current[3]) & virgin[3])) return 1;

  }

  return 0;

}

#endif

/* Returns 1 if a block of words (a multiple of PACK_SIZE bytes) is not 0. */
static inline u32 map_chunk_nonzero(const u64 *current, u32 words) {

  u32 i = 0;

#if defined(__AVX2__)
  __m256i acc = _mm256_setzero_si256();
  for (; i + 4 <= words; i += 4) {

    acc = _mm256_or_si256(acc,
                          _mm256_loadu_si256((const __m256i *)(current + i)));

  }

  if (!_mm256_testz_si256(acc, acc)) { return 1; }
#endif

  u64 rest = 0;
  for (; i < words; ++i) {

    rest |= current[i];

  }

  return rest != 0;

}

/* The same result as skim() for the full map, but with the map summary (see
   MAP_SUMMARY_SHIFT in config.h), if the forkserver has one.

   If the summary is valid, only the marked chunks can contain data, and only
   these are checked. If it is stale, all chunks are read, and each chunk that
   is not 0 gets a mark. After a complete scan the summary is valid: then
   afl_fsrv_clear_map() and later scans of this run use the fast path. */

static inline u32 skim_summary(afl_forkserver_t *fsrv, const u64 *virgin) {

  const u64 *current = (const u64 *)fsrv->trace_bits;
  size_t     map_words = fsrv->map_size >> 3;
  u8        *hdr = afl_fsrv_map_summary(fsrv);
  u32        chunks = MAP_SUMMARY_CHUNKS(fsrv->map_size);
  const u32  chunk_words = MAP_SUMMARY_CHUNK >> 3;

  if (unlikely(!hdr || chunks > afl_fsrv_map_summary_cap(fsrv) ||
               (map_words << 3) % PACK_SIZE)) {

    return skim(virgin, current, current + map_words);

  }

  u8 *marks = hdr + MAP_SUMMARY_HDR;
  u8  stale = hdr[MAP_SUMMARY_HDR_STALE];

  for (u32 c = 0; c < chunks; ++c) {

    if (likely(!stale)) {

      c = map_summary_next(marks, chunks, c);
      if (c >= chunks) { break; }

    }

    /* Only the last chunk can be shorter. */
    size_t beg = (size_t)c * chunk_words;
    size_t end = beg + chunk_words;
    if (unlikely(end > map_words)) { end = map_words; }

    if (unlikely(stale)) {

      if (likely(!map_chunk_nonzero(current + beg, (u32)(end - beg)))) {

        continue;

      }

      marks[c] = 1;

    }

    if (unlikely(skim(virgin + beg, current + beg, current + end))) {

      return 1;

    }

  }

  hdr[MAP_SUMMARY_HDR_STALE] = 0;
  return 0;

}

#endif

