/*
 * Skeleton for AES round-function oracle
 * - Enforces the CLI contract from the assignment
 * - Students fill in SubBytes/InvSubBytes, ShiftRows/InvShiftRows,
 *   MixColumns/InvMixColumns (AddRoundKey is provided).
 *
 * Build:   make
 * Run:     ./AES_Functions
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdbool.h>
#include "aes_tables.h"

/* =========================
   Required function signatures
   ========================= */
void SubBytes(uint8_t state[16]);
void InvSubBytes(uint8_t state[16]);

void ShiftRows(uint8_t state[16]);
void InvShiftRows(uint8_t state[16]);

void MixColumns(uint8_t state[16]);
void InvMixColumns(uint8_t state[16]);

void AddRoundKey(uint8_t state[16], const uint8_t roundKey[16]);

/* =========================
   Helpful macros & helpers
   Column-major mapping: idx = c*4 + r
   ========================= */
#define IDX(r,c) ((c)*4 + (r))
#define LINE_MAX_LEN 256

static inline void trim_trailing_newline(char *s) {
    size_t n = strlen(s);
    if (n && s[n-1] == '\n') s[n-1] = '\0';
}

static inline void to_upper_hex(char *s) {
    for (; *s; ++s) *s = (char)toupper((unsigned char)*s);
}

static bool is_hex_string(const char *s) {
    if (!s || !*s) return false;
    for (const char *p = s; *p; ++p) {
        if (!isxdigit((unsigned char)*p)) return false;
    }
    return true;
}

/* Parse hex string (0..32 hex chars), pad with zeros to 16 bytes.
   If >32 hex chars, truncate to first 32.
   Returns true on success, false on invalid format (e.g., odd length) */
static bool parse_hex_to_16(const char *hex, uint8_t out16[16]) {
    size_t L = strlen(hex);
    if (L > 32) L = 32;                      // truncate
    if (L % 2 != 0) return false;            // must be even length
    if (L == 0) {                            // allow empty => all zeros
        memset(out16, 0, 16);
        return true;
    }
    if (!is_hex_string(hex)) return false;

    // parse pairs
    size_t bytes = L / 2;
    for (size_t i = 0; i < bytes; ++i) {
        char buf[3] = { hex[2*i], hex[2*i+1], '\0' };
        out16[i] = (uint8_t)strtoul(buf, NULL, 16);
    }
    // pad
    for (size_t i = bytes; i < 16; ++i) out16[i] = 0x00;
    return true;
}

static void print_state_line(const uint8_t state[16]) {
    // STATE=<32 uppercase hex>, no spaces
    fputs("STATE=", stdout);
    for (int i = 0; i < 16; ++i) {
        printf("%02X", state[i]);
    }
    fputc('\n', stdout);
    fflush(stdout);
}

/* Read a line; returns true if a line was read. */
static bool read_line(char buf[LINE_MAX_LEN]) {
    if (!fgets(buf, LINE_MAX_LEN, stdin)) return false;
    trim_trailing_newline(buf);
    return true;
}

/* =========================
   Command handling
   ========================= */
static void print_help(void) {
    puts("Commands:");
    puts("  HELP");
    puts("  SUB");
    puts("  INV_SUB");
    puts("  SHIFT");
    puts("  INV_SHIFT");
    puts("  MIX");
    puts("  INV_MIX");
    puts("  XOR <32-hex>");     // AddRoundKey
    puts("  RESET <0..32 hex>");// load new state (padded with zeros)
    puts("  PRINT");
    puts("  EXIT");
}

/* =========================
   AES round functions
   NOTE: Students should replace the TODO bodies with real implementations.
   ========================= */

void SubBytes(uint8_t state[16]) {
    for(int i = 0; i <= 15; i++) state[i] = SBOX[state[i]];
}

void InvSubBytes(uint8_t state[16]) {
    for(int i = 0; i <= 15; i++) state[i] = INV_SBOX[state[i]];
}

void ShiftRows(uint8_t state[16]) {
    /* TODO:
     *   - Treat as 4x4 matrix (row r, column c)
     *   - Left rotate row r by r positions
     *   - Column-major indexing via IDX(r,c)
     */
    (void)state;
}

void InvShiftRows(uint8_t state[16]) {
    /* TODO:
     *   - Right rotate row r by r positions (inverse of ShiftRows)
     */
    (void)state;
}

/* xtime helper (multiply by 0x02 in GF(2^8)) — useful for MixColumns */
static inline uint8_t xtime(uint8_t x){return (uint8_t)((x & 0x80) ? ((x << 1) ^ 0x1B) : (x << 1))};
static uint8_t mul9(uint8_t x){return xtime(xtime(xtime(x))) ^ x;}
static uint8_t mul11(uint8_t x){return xtime(xtime(xtime(x))) ^ xtime(x) ^ x;}
static uint8_t mul13(uint8_t x){return xtime(xtime(xtime(x))) ^ xtime(xtime(x)) ^ x;}
static uint8_t mul14(uint8_t x){return xtime(xtime(xtime(x))) ^ xtime(xtime(x)) ^ xtime(x);}


void MixColumns(uint8_t state[16]) {
    (void)state;
    uint8_t s0,s1,s2,s3;
    uint8_t t0,t1,t2,t3;

    for(int i = 0; i < 4; i++){
        s0 = state[IDX(0,i)];
        s1 = state[IDX(1,i)];
        s2 = state[IDX(2,i)];
        s3 = state[IDX(3,i)];

        t0 = xtime(s0) ^ (xtime(s1) ^ s1) ^ s2 ^ s3;
        t1 = s0 ^ xtime(s1) ^ (xtime(s2) ^ s2) ^ s3;
        t2 = s0 ^ s1 ^ xtime(s2) ^ (xtime(s3) ^ s3);
        t3 = (xtime(s0) ^ s0) ^ s1 ^ s2 ^ xtime(s3);

        state[IDX(0,i)] = t0;
        state[IDX(1,i)] = t1;
        state[IDX(2,i)] = t2;
        state[IDX(3,i)] = t3;
    }
}

void InvMixColumns(uint8_t state[16]) {
    uint8_t s0,s1,s2,s3;
    uint8_t t0,t1,t2,t3;

    for(int i = 0; i < 4; i++){
        s0 = state[IDX(0,i)];
        s1 = state[IDX(1,i)];
        s2 = state[IDX(2,i)];
        s3 = state[IDX(3,i)];

        t0 = mul14(s0) ^ mul11(s1) ^ mul13(s2) ^ mul9(s3);
        t1 = mul9(s0) ^ mul14(s1) ^ mul11(s2) ^ mul13(s3);
        t2 = mul13(s0) ^ mul9(s1) ^ mul14(s2) ^ mul11(s3);
        t3 = mul11(s0) ^ mul13(s1) ^ mul9(s2) ^ mul14(s3);

        state[IDX(0,i)] = t0;
        state[IDX(1,i)] = t1;
        state[IDX(2,i)] = t2;
        state[IDX(3,i)] = t3;
    }

}

void AddRoundKey(uint8_t state[16], const uint8_t roundKey[16]) {
    for (int i = 0; i < 16; ++i) state[i] ^= roundKey[i];
}

/* =========================
   Program entry & loop
   ========================= */

int main(void) {
    uint8_t state[16] = {0};

    /* 1) Initial plaintext prompt */
    puts("Enter plaintext hex (0..32 hex chars):");
    char line[LINE_MAX_LEN];
    while (1) {
        if (!read_line(line)) return 0; // EOF
        // Remove spaces
        char hex[LINE_MAX_LEN];
        size_t j = 0;
        for (size_t i = 0; line[i] && j+1 < sizeof(hex); ++i) {
            if (!isspace((unsigned char)line[i])) hex[j++] = line[i];
        }
        hex[j] = '\0';
        to_upper_hex(hex);

        if (strlen(hex) == 0 || (strlen(hex) % 2 == 0 && strlen(hex) <= 32 && is_hex_string(hex))) {
            if (!parse_hex_to_16(hex, state)) {
                puts("ERROR");
                continue;
            }
            print_state_line(state);
            break;
        } else {
            puts("ERROR");
        }
    }

    /* 2) Command loop */
    while (1) {
        puts("CMD? (type HELP)");
        if (!read_line(line)) break;

        // Split first token
        char *cmd = strtok(line, " \t");
        if (!cmd) { puts("ERROR"); continue; }

        // Uppercase command for case-insensitive match
        for (char *p = cmd; *p; ++p) *p = (char)toupper((unsigned char)*p);

        if (strcmp(cmd, "HELP") == 0) {
            print_help();
            continue;
        } else if (strcmp(cmd, "SUB") == 0) {
            SubBytes(state);
            print_state_line(state);
        } else if (strcmp(cmd, "INV_SUB") == 0) {
            InvSubBytes(state);
            print_state_line(state);
        } else if (strcmp(cmd, "SHIFT") == 0) {
            ShiftRows(state);
            print_state_line(state);
        } else if (strcmp(cmd, "INV_SHIFT") == 0) {
            InvShiftRows(state);
            print_state_line(state);
        } else if (strcmp(cmd, "MIX") == 0) {
            MixColumns(state);
            print_state_line(state);
        } else if (strcmp(cmd, "INV_MIX") == 0) {
            InvMixColumns(state);
            print_state_line(state);
        } else if (strcmp(cmd, "XOR") == 0) {
            char *arg = strtok(NULL, " \t");
            if (!arg) { puts("ERROR"); continue; }
            // Remove spaces in key and validate
            char keyhex[LINE_MAX_LEN];
            size_t j = 0;
            for (size_t i = 0; arg[i] && j+1 < sizeof(keyhex); ++i) {
                if (!isspace((unsigned char)arg[i])) keyhex[j++] = arg[i];
            }
            keyhex[j] = '\0';
            to_upper_hex(keyhex);

            if (strlen(keyhex) != 32 || !is_hex_string(keyhex)) {
                puts("ERROR");
                continue;
            }
            uint8_t key[16];
            if (!parse_hex_to_16(keyhex, key)) {
                puts("ERROR");
                continue;
            }
            AddRoundKey(state, key);
            print_state_line(state);
        } else if (strcmp(cmd, "RESET") == 0) {
            char *arg = strtok(NULL, " \t");
            if (!arg) arg = ""; // allow empty => zero state
            // strip spaces in provided hex
            char hex[LINE_MAX_LEN];
            size_t j = 0;
            for (size_t i = 0; arg[i] && j+1 < sizeof(hex); ++i) {
                if (!isspace((unsigned char)arg[i])) hex[j++] = arg[i];
            }
            hex[j] = '\0';
            to_upper_hex(hex);

            if ((strlen(hex) <= 32) && (strlen(hex) % 2 == 0) && (strlen(hex) == 0 || is_hex_string(hex))) {
                if (!parse_hex_to_16(hex, state)) { puts("ERROR"); continue; }
                print_state_line(state);
            } else {
                puts("ERROR");
            }
        } else if (strcmp(cmd, "PRINT") == 0) {
            print_state_line(state);
        } else if (strcmp(cmd, "EXIT") == 0) {
            break;
        } else {
            puts("ERROR");
        }
    }

    return 0;
}
