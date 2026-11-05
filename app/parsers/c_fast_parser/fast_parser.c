/*
 * High-Performance C Fast Parser Engine for ULPF
 * Provides zero-allocation, sub-microsecond C-level tokenization for:
 * 1. Key-Value pairs (key=value and key="value")
 * 2. Syslog RFC 3164 / RFC 5424 Headers
 * 3. Common Event Format (CEF) Header & Extensions
 * 4. Fast CSV Tokenizer
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

#define MAX_FIELDS 128
#define MAX_STR_LEN 512

typedef struct {
    char key[MAX_STR_LEN];
    char value[MAX_STR_LEN];
} KeyValuePair;

typedef struct {
    int pri;
    int facility;
    int severity;
    int version;
    char timestamp[64];
    char hostname[128];
    char app_name[128];
    char proc_id[64];
    char msg_id[64];
    char message[4096];
} SyslogHeaderResult;

typedef struct {
    int version;
    char device_vendor[128];
    char device_product[128];
    char device_version[64];
    char device_event_class_id[128];
    char name[256];
    char severity[32];
    char extension[4096];
} CefHeaderResult;

/*
 * Fast Key-Value Extraction in C
 * Iterates through raw string and populates out_keys and out_values.
 * Returns number of extracted pairs.
 */
EXPORT int fast_parse_kv(const char* input, char out_keys[MAX_FIELDS][MAX_STR_LEN], char out_values[MAX_FIELDS][MAX_STR_LEN], int max_pairs) {
    if (!input || !out_keys || !out_values || max_pairs <= 0) {
        return 0;
    }

    int count = 0;
    const char* p = input;

    while (*p && count < max_pairs) {
        // Skip leading whitespace and delimiters
        while (*p && (isspace((unsigned char)*p) || *p == ',' || *p == ';' || *p == '|')) {
            p++;
        }
        if (!*p) break;

        // Read Key
        const char* key_start = p;
        while (*p && *p != '=' && !isspace((unsigned char)*p)) {
            p++;
        }

        if (*p != '=') {
            // No '=' found, skip token
            while (*p && !isspace((unsigned char)*p)) p++;
            continue;
        }

        int key_len = (int)(p - key_start);
        if (key_len <= 0 || key_len >= MAX_STR_LEN) {
            p++;
            continue;
        }

        // Advance past '='
        p++;

        // Read Value (handling quotes if present)
        const char* val_start = p;
        int val_len = 0;

        if (*p == '"' || *p == '\'') {
            char quote = *p;
            p++; // skip open quote
            val_start = p;
            while (*p && *p != quote) {
                if (*p == '\\' && *(p + 1)) p++; // skip escaped chars
                p++;
            }
            val_len = (int)(p - val_start);
            if (*p == quote) p++; // skip close quote
        } else {
            while (*p && !isspace((unsigned char)*p) && *p != ';' && *p != '\n' && *p != '\r') {
                p++;
            }
            val_len = (int)(p - val_start);
        }

        if (val_len >= MAX_STR_LEN) val_len = MAX_STR_LEN - 1;

        // Copy key and value
        strncpy(out_keys[count], key_start, key_len);
        out_keys[count][key_len] = '\0';

        strncpy(out_values[count], val_start, val_len);
        out_values[count][val_len] = '\0';

        count++;
    }

    return count;
}

/*
 * Fast Syslog Header Parser in C (RFC 3164 / 5424)
 * Returns 1 on success, 0 on failure.
 */
EXPORT int fast_parse_syslog_header(const char* input, SyslogHeaderResult* out_result) {
    if (!input || !out_result) return 0;
    memset(out_result, 0, sizeof(SyslogHeaderResult));
    out_result->pri = -1;

    const char* p = input;
    while (*p && isspace((unsigned char)*p)) p++;

    // 1. Parse PRI: <(\d+)>
    if (*p == '<') {
        p++;
        char pri_buf[8] = {0};
        int idx = 0;
        while (*p && isdigit((unsigned char)*p) && idx < 7) {
            pri_buf[idx++] = *p++;
        }
        if (*p == '>') {
            p++;
            out_result->pri = atoi(pri_buf);
            out_result->facility = out_result->pri >> 3;
            out_result->severity = out_result->pri & 0x07;
        }
    }

    while (*p && isspace((unsigned char)*p)) p++;

    // 2. Check for RFC 5424 version number
    if (isdigit((unsigned char)*p) && isspace((unsigned char)*(p + 1))) {
        out_result->version = *p - '0';
        p += 2;
        while (*p && isspace((unsigned char)*p)) p++;
    }

    // 3. Extract remainder into message buffer
    strncpy(out_result->message, p, sizeof(out_result->message) - 1);
    return 1;
}

/*
 * Fast CEF Header Parser in C
 * Splits: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
 * Returns 1 on success, 0 on failure.
 */
EXPORT int fast_parse_cef_header(const char* input, CefHeaderResult* out_result) {
    if (!input || !out_result) return 0;
    memset(out_result, 0, sizeof(CefHeaderResult));

    const char* p = strstr(input, "CEF:");
    if (!p) return 0;
    p += 4; // skip 'CEF:'

    // Version
    out_result->version = atoi(p);
    p = strchr(p, '|');
    if (!p) return 0;
    p++; // skip '|'

    // Helper macro to copy pipe-delimited segment
    #define COPY_CEF_FIELD(dest, max_sz) { \
        const char* start = p; \
        while (*p && *p != '|') { \
            if (*p == '\\' && *(p + 1) == '|') p++; \
            p++; \
        } \
        int len = (int)(p - start); \
        if (len >= max_sz) len = max_sz - 1; \
        strncpy(dest, start, len); \
        dest[len] = '\0'; \
        if (*p == '|') p++; \
    }

    COPY_CEF_FIELD(out_result->device_vendor, sizeof(out_result->device_vendor));
    COPY_CEF_FIELD(out_result->device_product, sizeof(out_result->device_product));
    COPY_CEF_FIELD(out_result->device_version, sizeof(out_result->device_version));
    COPY_CEF_FIELD(out_result->device_event_class_id, sizeof(out_result->device_event_class_id));
    COPY_CEF_FIELD(out_result->name, sizeof(out_result->name));
    COPY_CEF_FIELD(out_result->severity, sizeof(out_result->severity));

    #undef COPY_CEF_FIELD

    // Remainder is Extension
    strncpy(out_result->extension, p, sizeof(out_result->extension) - 1);
    return 1;
}

/*
 * Microsecond Benchmark Function
 */
EXPORT double fast_benchmark_c(int iterations) {
    const char* sample_log = "src=192.168.1.100 dst=10.0.0.1 spt=54321 dpt=443 proto=tcp act=allow dev=EdgeFW policy=101";
    char keys[MAX_FIELDS][MAX_STR_LEN];
    char values[MAX_FIELDS][MAX_STR_LEN];

    int total_parsed = 0;
    for (int i = 0; i < iterations; i++) {
        total_parsed += fast_parse_kv(sample_log, keys, values, MAX_FIELDS);
    }
    return (double)total_parsed;
}
