#include "simd_parser.h"
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <immintrin.h> // For AVX2 Intrinsics

// Utility function for AVX2 high-speed delimiter search
static inline int find_char_avx2(const char *str, size_t len, char target) {
    size_t i = 0;
#if defined(__AVX2__)
    __m256i target_vec = _mm256_set1_epi8(target);
    for (; i + 32 <= len; i += 32) {
        __m256i data = _mm256_loadu_si256((const __m256i*)(str + i));
        __m256i cmp = _mm256_cmpeq_epi8(data, target_vec);
        int mask = _mm256_movemask_epi8(cmp);
        if (mask != 0) {
            // Find the exact index using __builtin_ctz (count trailing zeros)
            return i + __builtin_ctz(mask);
        }
    }
#endif
    // Scalar fallback
    for (; i < len; ++i) {
        if (str[i] == target) return i;
    }
    return -1;
}

static inline bool is_whitespace(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

KosmoporosLogFormat kosmoporos_detect_format(const char *raw, size_t len) {
    if (!raw || len == 0) return KOSMOPOROS_FORMAT_UNKNOWN;

    // Skip leading whitespace
    size_t i = 0;
    while (i < len && is_whitespace(raw[i])) i++;
    if (i >= len) return KOSMOPOROS_FORMAT_UNKNOWN;

    const char *p = raw + i;
    size_t rem = len - i;

    if (rem >= 4 && strncmp(p, "CEF:", 4) == 0) {
        return KOSMOPOROS_FORMAT_CEF;
    }
    if (rem >= 5 && strncmp(p, "LEEF:", 5) == 0) {
        return KOSMOPOROS_FORMAT_LEEF;
    }
    if (rem >= 1 && *p == '{') {
        return KOSMOPOROS_FORMAT_JSON;
    }
    if (rem >= 3 && *p == '<') {
        size_t k = 1;
        int pri_val = 0;
        while (k < rem && isdigit((unsigned char)p[k]) && k < 5) {
            pri_val = pri_val * 10 + (p[k] - '0');
            k++;
        }
        if (k < rem && p[k] == '>') {
            k++;
            if (k < rem && isdigit((unsigned char)p[k]) && (k + 1 < rem && p[k+1] == ' ')) {
                return KOSMOPOROS_FORMAT_SYSLOG_RFC5424;
            }
            return KOSMOPOROS_FORMAT_SYSLOG_RFC3164;
        }
    }

    // Check for key=value pattern
    size_t eq_count = 0;
    for (size_t idx = 0; idx < rem; ++idx) {
        if (p[idx] == '=' && idx > 0 && isalnum((unsigned char)p[idx-1])) {
            eq_count++;
            if (eq_count >= 2) return KOSMOPOROS_FORMAT_KV;
        }
    }

    return KOSMOPOROS_FORMAT_PLAINTEXT;
}

static void parse_kv_extension(const char *raw, size_t start, size_t len, KosmoporosFastParseResult *res) {
    size_t i = start;
    size_t end = start + len;

    while (i < end && res->kv_count < 64) {
        while (i < end && is_whitespace(raw[i])) i++;
        if (i >= end) break;

        size_t key_start = i;
        while (i < end && raw[i] != '=' && !is_whitespace(raw[i])) i++;
        if (i >= end || raw[i] != '=') break;

        size_t key_len = i - key_start;
        i++; // skip '='

        size_t val_start = i;
        size_t val_len = 0;

        if (i < end && raw[i] == '"') {
            i++;
            val_start = i;
            while (i < end && raw[i] != '"') {
                if (raw[i] == '\\' && i + 1 < end) i += 2;
                else i++;
            }
            val_len = i - val_start;
            if (i < end && raw[i] == '"') i++;
        } else {
            while (i < end && !is_whitespace(raw[i])) i++;
            val_len = i - val_start;
        }

        if (key_len > 0) {
            res->kv_pairs[res->kv_count].key.start = key_start;
            res->kv_pairs[res->kv_count].key.length = key_len;
            res->kv_pairs[res->kv_count].val.start = val_start;
            res->kv_pairs[res->kv_count].val.length = val_len;
            res->kv_count++;
        }
    }
}

static bool parse_cef(const char *raw, size_t len, KosmoporosFastParseResult *res) {
    res->format = KOSMOPOROS_FORMAT_CEF;
    int pos = find_char_avx2(raw, len, ':');
    if (pos == -1) return false;
    pos++; // Skip ':'

    KosmoporosSlice fields[8];
    int field_idx = 0;

    size_t start = pos;
    while (pos < len && field_idx < 7) {
        if (raw[pos] == '\\' && pos + 1 < len) {
            pos += 2;
            continue;
        }
        if (raw[pos] == '|') {
            fields[field_idx].start = start;
            fields[field_idx].length = pos - start;
            field_idx++;
            pos++;
            start = pos;
            continue;
        }
        pos++;
    }

    if (field_idx == 7) {
        fields[7].start = start;
        fields[7].length = len - start;
        field_idx = 8;
    }

    if (field_idx >= 7) {
        res->version = fields[0];
        res->vendor = fields[1];
        res->product = fields[2];
        res->hostname = fields[3]; // often version or device host
        res->event_id = fields[4];
        res->message = fields[5];
        res->severity = fields[6];
        if (field_idx == 8 && fields[7].length > 0) {
            parse_kv_extension(raw, fields[7].start, fields[7].length, res);
        }
        return true;
    }
    return false;
}

static bool parse_syslog(const char *raw, size_t len, KosmoporosFastParseResult *res, bool is_5424) {
    res->format = is_5424 ? KOSMOPOROS_FORMAT_SYSLOG_RFC5424 : KOSMOPOROS_FORMAT_SYSLOG_RFC3164;
    size_t pos = 0;
    if (raw[0] == '<') {
        size_t k = 1;
        int pri = 0;
        while (k < len && isdigit((unsigned char)raw[k]) && k < 5) {
            pri = pri * 10 + (raw[k] - '0');
            k++;
        }
        if (k < len && raw[k] == '>') {
            res->pri = pri;
            pos = k + 1;
        }
    }

    while (pos < len && is_whitespace(raw[pos])) pos++;
    size_t start = pos;

    if (is_5424) {
        // Skip version digit
        while (pos < len && isdigit((unsigned char)raw[pos])) pos++;
        while (pos < len && is_whitespace(raw[pos])) pos++;
        // Timestamp
        start = pos;
        while (pos < len && !is_whitespace(raw[pos])) pos++;
        res->timestamp.start = start;
        res->timestamp.length = pos - start;
        while (pos < len && is_whitespace(raw[pos])) pos++;
        // Hostname
        start = pos;
        while (pos < len && !is_whitespace(raw[pos])) pos++;
        res->hostname.start = start;
        res->hostname.length = pos - start;
        while (pos < len && is_whitespace(raw[pos])) pos++;
        // App name
        start = pos;
        while (pos < len && !is_whitespace(raw[pos])) pos++;
        res->app_name.start = start;
        res->app_name.length = pos - start;
    } else {
        // RFC3164 timestamp (typically e.g. "Jan 10 14:32:01")
        size_t spaces = 0;
        while (pos < len && spaces < 3) {
            if (raw[pos] == ' ') spaces++;
            pos++;
        }
        res->timestamp.start = start;
        res->timestamp.length = pos - start;
        while (pos < len && is_whitespace(raw[pos])) pos++;
        // Hostname
        start = pos;
        while (pos < len && !is_whitespace(raw[pos]) && raw[pos] != ':') pos++;
        res->hostname.start = start;
        res->hostname.length = pos - start;
    }

    while (pos < len && is_whitespace(raw[pos])) pos++;
    res->message.start = pos;
    res->message.length = len - pos;

    // Scan message for KV pairs
    if (res->message.length > 0) {
        parse_kv_extension(raw, res->message.start, res->message.length, res);
    }
    return true;
}

bool kosmoporos_fast_parse(const char *raw, size_t len, KosmoporosFastParseResult *result) {
    if (!raw || len == 0 || !result) return false;
    memset(result, 0, sizeof(KosmoporosFastParseResult));
    result->pri = -1;

    KosmoporosLogFormat fmt = kosmoporos_detect_format(raw, len);
    switch (fmt) {
        case KOSMOPOROS_FORMAT_CEF:
            return parse_cef(raw, len, result);
        case KOSMOPOROS_FORMAT_SYSLOG_RFC5424:
            return parse_syslog(raw, len, result, true);
        case KOSMOPOROS_FORMAT_SYSLOG_RFC3164:
            return parse_syslog(raw, len, result, false);
        case KOSMOPOROS_FORMAT_KV:
            result->format = KOSMOPOROS_FORMAT_KV;
            result->message.start = 0;
            result->message.length = len;
            parse_kv_extension(raw, 0, len, result);
            return true;
        case KOSMOPOROS_FORMAT_JSON:
            result->format = KOSMOPOROS_FORMAT_JSON;
            result->message.start = 0;
            result->message.length = len;
            return true;
        case KOSMOPOROS_FORMAT_PLAINTEXT:
        default:
            result->format = KOSMOPOROS_FORMAT_PLAINTEXT;
            result->message.start = 0;
            result->message.length = len;
            return true;
    }
}
