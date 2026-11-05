#ifndef KOSMOPOROS_SIMD_PARSER_H
#define KOSMOPOROS_SIMD_PARSER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    KOSMOPOROS_FORMAT_UNKNOWN = 0,
    KOSMOPOROS_FORMAT_CEF,
    KOSMOPOROS_FORMAT_LEEF,
    KOSMOPOROS_FORMAT_SYSLOG_RFC5424,
    KOSMOPOROS_FORMAT_SYSLOG_RFC3164,
    KOSMOPOROS_FORMAT_JSON,
    KOSMOPOROS_FORMAT_KV,
    KOSMOPOROS_FORMAT_PLAINTEXT
} KosmoporosLogFormat;

typedef struct {
    size_t start;
    size_t length;
} KosmoporosSlice;

typedef struct {
    KosmoporosSlice key;
    KosmoporosSlice val;
} KosmoporosKvPair;

typedef struct {
    KosmoporosLogFormat format;
    int pri;
    KosmoporosSlice timestamp;
    KosmoporosSlice hostname;
    KosmoporosSlice app_name;
    KosmoporosSlice vendor;
    KosmoporosSlice product;
    KosmoporosSlice version;
    KosmoporosSlice event_id;
    KosmoporosSlice severity;
    KosmoporosSlice message;
    
    size_t kv_count;
    KosmoporosKvPair kv_pairs[64];
} KosmoporosFastParseResult;

// Fast format detector
KosmoporosLogFormat kosmoporos_detect_format(const char *raw, size_t len);

// Zero-copy SIMD/pointer tokenizer
bool kosmoporos_fast_parse(const char *raw, size_t len, KosmoporosFastParseResult *result);

#ifdef __cplusplus
}
#endif

#endif // KOSMOPOROS_SIMD_PARSER_H
