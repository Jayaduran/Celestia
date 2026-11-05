#ifndef KOSMOPOROS_STATS_ENGINE_H
#define KOSMOPOROS_STATS_ENGINE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t total_events;
    uint64_t total_bytes;
    uint64_t total_errors;
    uint64_t total_cef;
    uint64_t total_syslog;
    uint64_t total_json;
    uint64_t total_leef;
    uint64_t total_kv;
    uint64_t total_plaintext;
    
    uint64_t threat_benign;
    uint64_t threat_suspicious;
    uint64_t threat_malicious;

    uint64_t merkle_blocks_sealed;
    uint64_t merkle_verifications_passed;
    uint64_t merkle_verifications_failed;

    double window_start_time;
    uint64_t window_events;
    double current_eps;
    double total_latency_us;
} KosmoporosStats;

void kosmoporos_stats_init(KosmoporosStats *stats);
void kosmoporos_stats_record_event(KosmoporosStats *stats, size_t byte_len, double latency_us, int format, int verdict);
void kosmoporos_stats_record_merkle_seal(KosmoporosStats *stats);
void kosmoporos_stats_record_merkle_verify(KosmoporosStats *stats, bool passed);
void kosmoporos_stats_snapshot(const KosmoporosStats *stats, KosmoporosStats *out);

#ifdef __cplusplus
}
#endif

#endif // KOSMOPOROS_STATS_ENGINE_H
