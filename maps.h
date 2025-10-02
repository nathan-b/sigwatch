#pragma once

#include "probe.h"

#define MAX_RINGBUF_ENTRIES (256 * 1024)

/**
 * The ring buffer for sending data to userspace.
 */
struct
{
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, MAX_RINGBUF_ENTRIES);
} ringbuf SEC(".maps");

/**
 * Signal filter map - if signal number is present with value 1, we capture it
 */
struct
{
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 64);  // Support signals 0-63
  __type(key, __u32);
  __type(value, __u8);
} signal_filter SEC(".maps");
