#include "stats_engine.h"
#include <string.h>
#include <time.h>

static double get_current_time_sec(void) {
    struct timespec ts;
#if defined(_WIN32)
    timespec_get(&ts, TIME_UTC);
#else
    clock_gettime(CLOCK_MONOTONIC, &ts);
#endif
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

void kosmoporos_stats_init(KosmoporosStats *stats) {
    if (!stats) return;
    memset(stats, 0, sizeof(KosmoporosStats));
    stats->window_start_time = get_current_time_sec();
}

void kosmoporos_stats_record_event(KosmoporosStats *stats, size_t byte_len, double latency_us, int format, int verdict) {
    if (!stats) return;

    stats->total_events++;
    stats->total_bytes += byte_len;
    stats->total_latency_us += latency_us;
    stats->window_events++;

    switch (format) {
        case 1: stats->total_cef++; break;
        case 2: stats->total_leef++; break;
        case 3:
        case 4: stats->total_syslog++; break;
        case 5: stats->total_json++; break;
        case 6: stats->total_kv++; break;
        default: stats->total_plaintext++; break;
    }

    switch (verdict) {
        case 0: stats->threat_benign++; break;
        case 1: stats->threat_suspicious++; break;
        case 2: stats->threat_malicious++; break;
        default: break;
    }

    double now = get_current_time_sec();
    double elapsed = now - stats->window_start_time;
    if (elapsed >= 1.0) {
        stats->current_eps = (double)stats->window_events / elapsed;
        stats->window_start_time = now;
        stats->window_events = 0;
    }
}

void kosmoporos_stats_record_merkle_seal(KosmoporosStats *stats) {
    if (!stats) return;
    stats->merkle_blocks_sealed++;
}

void kosmoporos_stats_record_merkle_verify(KosmoporosStats *stats, bool passed) {
    if (!stats) return;
    if (passed) {
        stats->merkle_verifications_passed++;
    } else {
        stats->merkle_verifications_failed++;
    }
}

void kosmoporos_stats_snapshot(const KosmoporosStats *stats, KosmoporosStats *out) {
    if (!stats || !out) return;
    memcpy(out, stats, sizeof(KosmoporosStats));
}
