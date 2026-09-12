/*
 * Bitcoin Seed Finder - Template Mode (Parallel)
 *
 * Brute-forces BIP39 mnemonic phrases matching a template (with '*' wildcards)
 * and a target hash160, using BIP44/BIP49/BIP84 derivation paths.
 *
 * Build (MSVC):
 *   cl /O2 /W3 seedfinder.c /I<openssl>\include /I<secp256k1>\include ^
 *      /link /LIBPATH:<openssl>\lib /LIBPATH:<secp256k1>\lib ^
 *      libcrypto.lib libsecp256k1.lib
 *
 * Build (MinGW):
 *   gcc -O2 -o seedfinder.exe seedfinder.c -lcrypto -lsecp256k1
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <windows.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/ripemd.h>

#include <secp256k1.h>

// ===== Default settings =====
#define DEFAULT_THREADS      2
#define DEFAULT_SEED_WORDS   12
#define DEFAULT_CHUNK        1000
#define DEFAULT_DERIVATION   84
#define DEFAULT_TPL          "tpl.txt"
#define DEFAULT_WL           "words.txt"
#define DEFAULT_MODE         "seq"
#define DEFAULT_OUT          "found_seed.txt"

// ===== Limits =====
#define MAX_WORD_LEN         32
#define MAX_KNOWN_WORDS      2048
#define BIP39_WORD_COUNT     2048
#define MAX_SEED_WORDS       24
#define MAX_BITS             (MAX_SEED_WORDS * 11)
#define MAX_MNEMONIC_LEN     1024

// ===== Forward declarations =====
int word_to_index(const char* word);

// ===== Global state: BIP39 and user wordlists =====
static char bip39_words[BIP39_WORD_COUNT][MAX_WORD_LEN] = {0};
static char known_words[MAX_KNOWN_WORDS][MAX_WORD_LEN] = {0};
static int  known_bip39_indices[MAX_KNOWN_WORDS];
static int  known_word_lengths[MAX_KNOWN_WORDS];
static int  known_count = 0;

// ===== Global state: template =====
static char template_words[MAX_SEED_WORDS][MAX_WORD_LEN] = {0};
static int  template_is_wildcard[MAX_SEED_WORDS] = {0};
static int  wildcard_positions[MAX_SEED_WORDS];
static int  template_word_lengths[MAX_SEED_WORDS];
static int  position_to_wildcard_idx[MAX_SEED_WORDS];
static int  wildcard_count = 0;

// ===== Global state: crypto =====
static secp256k1_context* secp_ctx = NULL;

// ===== Global state: runtime =====
static volatile LONG       next_start_index = 0;
static unsigned long long  total_combinations = 0;
static uint8_t             target_hash160_from_arg[20] = {0};
static int                 has_target_from_arg = 0;
static char                found_mnemonic[MAX_MNEMONIC_LEN] = {0};
static int                 seed_found_flag = 0;

// ===== Runtime settings (populated from CLI) =====
static int  NUM_THREADS      = DEFAULT_THREADS;
static int  SEED_WORDS_COUNT = DEFAULT_SEED_WORDS;
static int  CHUNK_SIZE       = DEFAULT_CHUNK;
static int  DERIVATION_TYPE  = DEFAULT_DERIVATION;
static char TPL_FILE[256]    = DEFAULT_TPL;
static char WL_FILE[256]     = DEFAULT_WL;
static char MODE[8]          = DEFAULT_MODE;
static char OUT_FILE[256]    = DEFAULT_OUT;

// ===== Precomputed checksum context =====
typedef struct {
    uint8_t base_entropy[32];
    uint8_t base_checksum_bits;
    int     wildcard_bit_offsets[MAX_SEED_WORDS];
    int     entropy_size;
    int     checksum_bits;
    int     cs_bit_start;
    int     template_word_indices[MAX_SEED_WORDS];
} PrecomputedChecksum;

static PrecomputedChecksum precomp;

// ===== Shared state between threads =====
typedef struct {
    uint8_t         target_hash160[20];
    volatile LONG   found;
    volatile uint64_t processed;
    volatile uint64_t valid_count;
    volatile uint64_t total;
} SharedState;

// ===== Derivation paths (BIP44 / BIP49 / BIP84) =====
static const uint32_t derivation_path_bip44[5] = {
    0x80000000u + 44, 0x80000000u, 0x80000000u, 0, 0
};
static const uint32_t derivation_path_bip49[5] = {
    0x80000000u + 49, 0x80000000u, 0x80000000u, 0, 0
};
static const uint32_t derivation_path_bip84[5] = {
    0x80000000u + 84, 0x80000000u, 0x80000000u, 0, 0
};
static const uint32_t* derivation_path = derivation_path_bip84;
static const int       PATH_LEN        = 5;

static void set_derivation_path(int type) {
    switch (type) {
        case 44: derivation_path = derivation_path_bip44; break;
        case 49: derivation_path = derivation_path_bip49; break;
        case 84:
        default: derivation_path = derivation_path_bip84; break;
    }
}

static const char* get_derivation_name(int type) {
    switch (type) {
        case 44: return "BIP44 (m/44'/0'/0'/0/0)";
        case 49: return "BIP49 (m/49'/0'/0'/0/0)";
        case 84:
        default: return "BIP84 (m/84'/0'/0'/0/0)";
    }
}

// ===== Small helpers =====
static void print_separator(void) {
    printf("============================================================\n");
}

// Overflow-safe power for unsigned long long. Returns 0 on overflow.
static unsigned long long pow_ull(int base, int exp) {
    unsigned long long result = 1;
    for (int i = 0; i < exp; i++) {
        if (base != 0 && result > (unsigned long long)-1 / (unsigned long long)base) {
            return 0;
        }
        result *= (unsigned long long)base;
    }
    return result;
}

// Thread-safe PRNG (xorshift64*). Seed must be non-zero.
typedef struct { uint64_t s; } Rng;

static uint64_t rng_next(Rng* r) {
    uint64_t x = r->s;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    r->s = x;
    return x * 0x2545F4914F6CDD1DULL;
}

static uint64_t rng_bounded(Rng* r, uint64_t bound) {
    if (bound == 0) return 0;
    // Rejection sampling to avoid modulo bias.
    uint64_t threshold = (uint64_t)(-bound) % bound;
    for (;;) {
        uint64_t v = rng_next(r);
        if (v >= threshold) return v % bound;
    }
}

// ===== Help =====
static void print_help(void) {
    printf("Usage: seedfinder.exe -t <threads> -slen <12|24> -tpl <file> -wl <file> "
           "-dv <44|49|84> -ch <chunk_size> -hash <hash160> -mode <seq|rnd> -out <file>\n\n");
    printf("Options:\n");
    printf("  -t    <num>      Number of threads (default: %d)\n", DEFAULT_THREADS);
    printf("  -slen <12|24>    Seed length in words (default: %d)\n", DEFAULT_SEED_WORDS);
    printf("  -tpl  <file>     Template file with '*' for unknown words (default: %s)\n", DEFAULT_TPL);
    printf("  -wl   <file>     Wordlist file for substitution (default: %s)\n", DEFAULT_WL);
    printf("  -dv   <44|49|84> Derivation path (default: %d):\n", DEFAULT_DERIVATION);
    printf("                     44 - BIP44 (Legacy P2PKH)\n");
    printf("                     49 - BIP49 (SegWit P2SH-P2WPKH)\n");
    printf("                     84 - BIP84 (Native SegWit P2WPKH)\n");
    printf("  -ch   <num>      Chunk size per thread (default: %d)\n", DEFAULT_CHUNK);
    printf("  -hash <hex>      Target hash160 (40 hex chars). If omitted, reads hash160.txt\n");
    printf("  -mode <seq|rnd>  Search mode (default: %s):\n", DEFAULT_MODE);
    printf("                     seq - sequential (deterministic, stops at 100%%)\n");
    printf("                     rnd - random (infinite random search until found)\n");
    printf("  -out  <file>     Output file for found seed (default: %s)\n", DEFAULT_OUT);
    printf("  -h               Show this help\n\n");
    printf("Example:\n");
    printf("  seedfinder.exe -t 16 -slen 12 -tpl mytemplate.txt -wl mywords.txt "
           "-dv 84 -ch 2000 -hash 45a5ca918c5f04f81d8099e3e044ba9645c55cf9 -mode rnd -out result.txt\n");
    printf("  seedfinder.exe -t 8 -slen 24 -dv 49 -mode seq\n");
    printf("  seedfinder.exe -h\n");
}

// ===== Argument parsing =====
// Returns 1 to continue, 0 to exit.
static int parse_args(int argc, char* argv[]) {
    if (argc == 1) {
        printf("[!] No arguments provided.\n\n");
        print_help();
        return 0;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_help();
            return 0;
        }
        else if (strcmp(argv[i], "-t") == 0) {
            if (i + 1 >= argc) { printf("[!] -t requires a value\n"); return 0; }
            NUM_THREADS = atoi(argv[++i]);
            if (NUM_THREADS < 1 || NUM_THREADS > 1024) {
                printf("[!] -t must be between 1 and 1024\n"); return 0;
            }
        }
        else if (strcmp(argv[i], "-slen") == 0) {
            if (i + 1 >= argc) { printf("[!] -slen requires a value\n"); return 0; }
            SEED_WORDS_COUNT = atoi(argv[++i]);
            if (SEED_WORDS_COUNT != 12 && SEED_WORDS_COUNT != 24) {
                printf("[!] -slen must be 12 or 24\n"); return 0;
            }
        }
        else if (strcmp(argv[i], "-tpl") == 0) {
            if (i + 1 >= argc) { printf("[!] -tpl requires a value\n"); return 0; }
            strncpy(TPL_FILE, argv[++i], sizeof(TPL_FILE) - 1);
            TPL_FILE[sizeof(TPL_FILE) - 1] = '\0';
        }
        else if (strcmp(argv[i], "-wl") == 0) {
            if (i + 1 >= argc) { printf("[!] -wl requires a value\n"); return 0; }
            strncpy(WL_FILE, argv[++i], sizeof(WL_FILE) - 1);
            WL_FILE[sizeof(WL_FILE) - 1] = '\0';
        }
        else if (strcmp(argv[i], "-dv") == 0) {
            if (i + 1 >= argc) { printf("[!] -dv requires a value\n"); return 0; }
            DERIVATION_TYPE = atoi(argv[++i]);
            if (DERIVATION_TYPE != 44 && DERIVATION_TYPE != 49 && DERIVATION_TYPE != 84) {
                printf("[!] -dv must be 44, 49 or 84\n"); return 0;
            }
        }
        else if (strcmp(argv[i], "-ch") == 0) {
            if (i + 1 >= argc) { printf("[!] -ch requires a value\n"); return 0; }
            CHUNK_SIZE = atoi(argv[++i]);
            if (CHUNK_SIZE < 1 || CHUNK_SIZE > 1000000) {
                printf("[!] -ch must be between 1 and 1000000\n"); return 0;
            }
        }
        else if (strcmp(argv[i], "-hash") == 0) {
            if (i + 1 >= argc) { printf("[!] -hash requires a hash160 value\n"); return 0; }
            const char* hex = argv[++i];
            if (strlen(hex) != 40) {
                printf("[!] -hash must be exactly 40 hex characters\n"); return 0;
            }
            for (int j = 0; j < 20; j++) {
                unsigned int byte;
                if (sscanf(hex + j * 2, "%2x", &byte) != 1) {
                    printf("[!] Invalid hex string: %s\n", hex); return 0;
                }
                target_hash160_from_arg[j] = (uint8_t)byte;
            }
            has_target_from_arg = 1;
        }
        else if (strcmp(argv[i], "-mode") == 0) {
            if (i + 1 >= argc) { printf("[!] -mode requires a value\n"); return 0; }
            strncpy(MODE, argv[++i], sizeof(MODE) - 1);
            MODE[sizeof(MODE) - 1] = '\0';
            if (strcmp(MODE, "seq") != 0 && strcmp(MODE, "rnd") != 0) {
                printf("[!] -mode must be 'seq' or 'rnd'\n"); return 0;
            }
        }
        else if (strcmp(argv[i], "-out") == 0) {
            if (i + 1 >= argc) { printf("[!] -out requires a value\n"); return 0; }
            strncpy(OUT_FILE, argv[++i], sizeof(OUT_FILE) - 1);
            OUT_FILE[sizeof(OUT_FILE) - 1] = '\0';
        }
        else {
            printf("[!] Unknown option: %s\n", argv[i]);
            print_help();
            return 0;
        }
    }
    return 1;
}

// ===== File loading =====
static int load_bip39_wordlist(const char* filename) {
    FILE* f = fopen(filename, "r");
    if (!f) return -1;
    int count = 0;
    char line[256];
    while (fgets(line, sizeof(line), f) && count < BIP39_WORD_COUNT) {
        line[strcspn(line, "\r\n")] = 0;
        if (strlen(line) == 0) continue;
        memset(bip39_words[count], 0, MAX_WORD_LEN);
        strncpy(bip39_words[count], line, MAX_WORD_LEN - 1);
        count++;
    }
    fclose(f);
    return count;
}

static int load_known_words(const char* filename) {
    FILE* f = fopen(filename, "r");
    if (!f) return -1;
    known_count = 0;
    char line[256];
    while (fgets(line, sizeof(line), f) && known_count < MAX_KNOWN_WORDS) {
        line[strcspn(line, "\r\n")] = 0;

        // Trim leading/trailing whitespace.
        char* start = line;
        while (*start == ' ' || *start == '\t') start++;
        char* end = start + strlen(start);
        while (end > start && (end[-1] == ' ' || end[-1] == '\t')) end--;
        *end = '\0';

        if (strlen(start) == 0) continue;

        // Skip duplicates.
        int dup = 0;
        for (int i = 0; i < known_count; i++) {
            if (strcmp(known_words[i], start) == 0) { dup = 1; break; }
        }
        if (dup) continue;

        memset(known_words[known_count], 0, MAX_WORD_LEN);
        strncpy(known_words[known_count], start, MAX_WORD_LEN - 1);

        // Precompute BIP39 index.
        known_bip39_indices[known_count] = word_to_index(start);
        if (known_bip39_indices[known_count] < 0) {
            printf("[!] Word not in BIP39: %s\n", start);
            fclose(f);
            return -1;
        }
        known_word_lengths[known_count] = (int)strlen(start);
        known_count++;
    }
    fclose(f);
    return known_count;
}

static int load_template(const char* filename) {
    FILE* f = fopen(filename, "r");
    if (!f) return -1;
    char line[1024];
    if (fgets(line, sizeof(line), f) == NULL) { fclose(f); return -1; }
    fclose(f);
    line[strcspn(line, "\r\n")] = 0;

    memset(template_words, 0, sizeof(template_words));
    memset(template_is_wildcard, 0, sizeof(template_is_wildcard));
    wildcard_count = 0;

    char* token = strtok(line, " ");
    int pos = 0;
    while (token && pos < SEED_WORDS_COUNT) {
        if (strcmp(token, "*") == 0) {
            template_is_wildcard[pos] = 1;
            wildcard_positions[wildcard_count++] = pos;
        } else {
            strncpy(template_words[pos], token, MAX_WORD_LEN - 1);
            template_is_wildcard[pos] = 0;
        }
        pos++;
        token = strtok(NULL, " ");
    }

    if (pos != SEED_WORDS_COUNT) return -1;

    total_combinations = pow_ull(known_count, wildcard_count);
    if (total_combinations == 0 && wildcard_count > 0) {
        printf("[!] Combination count overflows 64 bits\n");
        return -1;
    }

    // Map template position -> wildcard index.
    for (int i = 0; i < SEED_WORDS_COUNT; i++) {
        position_to_wildcard_idx[i] = -1;
    }
    for (int i = 0; i < wildcard_count; i++) {
        position_to_wildcard_idx[wildcard_positions[i]] = i;
    }

    // Precompute fixed word lengths.
    for (int i = 0; i < SEED_WORDS_COUNT; i++) {
        if (!template_is_wildcard[i]) {
            template_word_lengths[i] = (int)strlen(template_words[i]);
        }
    }

    printf("[*] Template:\n");
    for (int i = 0; i < SEED_WORDS_COUNT; i++) {
        printf("    [%d] %s\n", i, template_is_wildcard[i] ? "*" : template_words[i]);
    }
    printf("[*] Wildcards: %d\n", wildcard_count);
    printf("[*] Combinations: %llu\n", total_combinations);
    return 0;
}

static int load_target_hash160(const char* filename, uint8_t* hash160_out) {
    FILE* f = fopen(filename, "r");
    if (!f) return -1;
    char hex[128];
    if (fgets(hex, sizeof(hex), f) == NULL) { fclose(f); return -1; }
    fclose(f);
    hex[strcspn(hex, "\r\n")] = 0;
    if (strlen(hex) != 40) return -1;
    for (int i = 0; i < 20; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        hash160_out[i] = (uint8_t)byte;
    }
    return 0;
}

// ===== BIP39 lookup =====
int word_to_index(const char* word) {
    int left = 0, right = BIP39_WORD_COUNT - 1;
    while (left <= right) {
        int mid = (left + right) / 2;
        int cmp = strcmp(word, bip39_words[mid]);
        if (cmp == 0) return mid;
        if (cmp < 0) right = mid - 1;
        else left = mid + 1;
    }
    return -1;
}

// ===== Checksum precomputation =====
static void precompute_checksum(void) {
    memset(&precomp, 0, sizeof(precomp));

    precomp.entropy_size  = (SEED_WORDS_COUNT == 12) ? 16 : 32;
    precomp.checksum_bits = (SEED_WORDS_COUNT == 12) ? 4  : 8;
    precomp.cs_bit_start  = precomp.entropy_size * 8;

    // Resolve fixed template words to BIP39 indices.
    for (int i = 0; i < SEED_WORDS_COUNT; i++) {
        if (!template_is_wildcard[i]) {
            precomp.template_word_indices[i] = word_to_index(template_words[i]);
            if (precomp.template_word_indices[i] < 0) {
                printf("[!] Word not found in BIP39: %s\n", template_words[i]);
                exit(1);
            }
        }
    }

    // Build base bit array with wildcards filled with zeros.
    uint8_t all_bits[MAX_BITS];
    memset(all_bits, 0, sizeof(all_bits));
    int bit_pos = 0;

    for (int i = 0; i < SEED_WORDS_COUNT; i++) {
        precomp.wildcard_bit_offsets[i] = bit_pos;
        if (!template_is_wildcard[i]) {
            int idx = precomp.template_word_indices[i];
            for (int b = 10; b >= 0; b--) {
                all_bits[bit_pos++] = (idx >> b) & 1;
            }
        } else {
            bit_pos += 11;
        }
    }

    // Snapshot base entropy.
    memset(precomp.base_entropy, 0, sizeof(precomp.base_entropy));
    for (int i = 0; i < precomp.entropy_size; i++) {
        for (int b = 0; b < 8; b++) {
            precomp.base_entropy[i] = (precomp.base_entropy[i] << 1) | all_bits[i * 8 + b];
        }
    }

    // Snapshot base checksum bits.
    precomp.base_checksum_bits = 0;
    for (int b = 0; b < precomp.checksum_bits; b++) {
        precomp.base_checksum_bits =
            (precomp.base_checksum_bits << 1) | all_bits[precomp.cs_bit_start + b];
    }
}

// Write 11 bits of `index` starting at `bit_offset` into entropy/checksum.
static inline void set_11_bits(uint8_t* entropy, int bit_offset, int index,
                               uint8_t* cs_bits, int cs_bit_start, int checksum_bits) {
    for (int b = 10; b >= 0; b--) {
        int pos = bit_offset + (10 - b);
        int val = (index >> b) & 1;

        if (pos < cs_bit_start) {
            int byte_idx = pos / 8;
            int bit_idx  = 7 - (pos % 8);
            if (val) entropy[byte_idx] |=  (1 << bit_idx);
            else     entropy[byte_idx] &= ~(1 << bit_idx);
        } else {
            int cb = pos - cs_bit_start;
            if (cb < checksum_bits) {
                if (val) *cs_bits |=  (1 << (checksum_bits - 1 - cb));
                else     *cs_bits &= ~(1 << (checksum_bits - 1 - cb));
            }
        }
    }
}

// Fast checksum check for a set of wildcard BIP39 indices.
static inline int fast_checksum_check(const int wildcard_indices[]) {
    uint8_t entropy[32];
    memcpy(entropy, precomp.base_entropy, precomp.entropy_size);

    uint8_t cs_bits = precomp.base_checksum_bits;
    for (int w = 0; w < wildcard_count; w++) {
        int bit_off = precomp.wildcard_bit_offsets[wildcard_positions[w]];
        set_11_bits(entropy, bit_off, wildcard_indices[w],
                    &cs_bits, precomp.cs_bit_start, precomp.checksum_bits);
    }

    uint8_t sha256_hash[32];
    SHA256(entropy, precomp.entropy_size, sha256_hash);
    uint8_t expected = sha256_hash[0] >> (8 - precomp.checksum_bits);
    return cs_bits == expected;
}

// Legacy checksum for self-test only.
static int check_checksum_legacy(const char words[MAX_SEED_WORDS][MAX_WORD_LEN]) {
    uint8_t all_bits[MAX_BITS];
    int bit_pos = 0;
    for (int i = 0; i < SEED_WORDS_COUNT; i++) {
        int idx = word_to_index(words[i]);
        if (idx < 0) return 0;
        for (int bit = 10; bit >= 0; bit--) all_bits[bit_pos++] = (idx >> bit) & 1;
    }

    int entropy_size  = (SEED_WORDS_COUNT == 12) ? 16 : 32;
    int checksum_bits = (SEED_WORDS_COUNT == 12) ? 4  : 8;
    int entropy_bits  = entropy_size * 8;

    uint8_t entropy[32];
    memset(entropy, 0, sizeof(entropy));
    for (int i = 0; i < entropy_size; i++) {
        for (int bit = 0; bit < 8; bit++) {
            entropy[i] = (entropy[i] << 1) | all_bits[i * 8 + bit];
        }
    }

    uint8_t actual_checksum = 0;
    for (int bit = 0; bit < checksum_bits; bit++) {
        actual_checksum = (actual_checksum << 1) | all_bits[entropy_bits + bit];
    }

    uint8_t sha256_hash[32];
    SHA256(entropy, entropy_size, sha256_hash);
    uint8_t expected_checksum = sha256_hash[0] >> (8 - checksum_bits);

    return actual_checksum == expected_checksum;
}

// ===== Crypto helpers =====
static void pbkdf2_sha512(const char* mnemonic, size_t mnemonic_len, uint8_t* seed_out) {
    PKCS5_PBKDF2_HMAC(mnemonic, (int)mnemonic_len,
                      (const unsigned char*)"mnemonic", 8,
                      2048, EVP_sha512(), 64, seed_out);
}

static void ripemd160_hash(const uint8_t* input, size_t len, uint8_t* output) {
    unsigned int out_len = 20;
    EVP_Digest(input, len, output, &out_len, EVP_ripemd160(), NULL);
}

static void bip32_master_key(const uint8_t* seed, uint8_t* master_key, uint8_t* chain_code) {
    uint8_t hmac_result[64];
    unsigned int hmac_len = 64;
    HMAC(EVP_sha512(), "Bitcoin seed", 12, seed, 64, hmac_result, &hmac_len);
    memcpy(master_key, hmac_result, 32);
    memcpy(chain_code, hmac_result + 32, 32);
}

static void bip32_derive(const uint8_t* parent_key, const uint8_t* parent_chain,
                         uint32_t index, uint8_t* child_key, uint8_t* child_chain) {
    uint8_t data[37] = {0};
    uint8_t hmac_result[64];
    unsigned int hmac_len = 64;

    if (index >= 0x80000000u) {
        data[0] = 0;
        memcpy(data + 1, parent_key, 32);
    } else {
        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_create(secp_ctx, &pubkey, parent_key)) {
            memset(child_key, 0, 32);
            memset(child_chain, 0, 32);
            return;
        }
        uint8_t pubkey_serialized[33];
        size_t pubkey_len = 33;
        secp256k1_ec_pubkey_serialize(secp_ctx, pubkey_serialized, &pubkey_len,
                                      &pubkey, SECP256K1_EC_COMPRESSED);
        memcpy(data, pubkey_serialized, 33);
    }

    data[33] = (uint8_t)(index >> 24);
    data[34] = (uint8_t)(index >> 16);
    data[35] = (uint8_t)(index >> 8);
    data[36] = (uint8_t)(index);

    HMAC(EVP_sha512(), parent_chain, 32, data, 37, hmac_result, &hmac_len);

    // child_key = (parent_key + IL) mod n
    uint8_t carry = 0;
    for (int i = 31; i >= 0; i--) {
        uint16_t sum = (uint16_t)parent_key[i] + hmac_result[i] + carry;
        child_key[i] = sum & 0xFF;
        carry = (uint8_t)(sum >> 8);
    }

    static const uint8_t n[32] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
    };

    if (carry || memcmp(child_key, n, 32) >= 0) {
        int borrow = 0;
        for (int i = 31; i >= 0; i--) {
            int16_t diff = (int16_t)child_key[i] - n[i] - borrow;
            if (diff < 0) { diff += 256; borrow = 1; }
            else          { borrow = 0; }
            child_key[i] = (uint8_t)(diff & 0xFF);
        }
    }

    memcpy(child_chain, hmac_result + 32, 32);
}

static void compute_hash160(const uint8_t* private_key, uint8_t* hash160_out) {
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(secp_ctx, &pubkey, private_key)) {
        memset(hash160_out, 0, 20);
        return;
    }
    uint8_t pubkey_serialized[33];
    size_t pubkey_len = 33;
    secp256k1_ec_pubkey_serialize(secp_ctx, pubkey_serialized, &pubkey_len,
                                  &pubkey, SECP256K1_EC_COMPRESSED);
    uint8_t sha256_hash[32];
    SHA256(pubkey_serialized, 33, sha256_hash);
    ripemd160_hash(sha256_hash, 32, hash160_out);
}

// ===== Worker thread =====
static DWORD WINAPI worker_thread(LPVOID arg) {
    SharedState* state = (SharedState*)arg;
    int is_rnd = (strcmp(MODE, "rnd") == 0);

    // Per-thread PRNG seed.
    Rng rng;
    rng.s = ((uint64_t)time(NULL) << 32)
          ^ ((uint64_t)GetCurrentThreadId() << 16)
          ^ ((uint64_t)GetTickCount64());
    if (rng.s == 0) rng.s = 0x9E3779B97F4A7C15ULL;

    while (!state->found) {
        LONG start = InterlockedIncrement(&next_start_index);

        unsigned long long chunk_begin = (unsigned long long)start * (unsigned long long)CHUNK_SIZE;
        unsigned long long chunk_end   = chunk_begin + (unsigned long long)CHUNK_SIZE;

        for (unsigned long long combo = chunk_begin;
             combo < chunk_end && !state->found;
             combo++) {

            unsigned long long combo_idx;
            if (is_rnd) {
                combo_idx = rng_bounded(&rng, total_combinations);
            } else {
                if (combo >= total_combinations) return 0;
                combo_idx = combo;
            }

            // Decompose combo index into per-wildcard word indices.
            int wildcard_indices[MAX_SEED_WORDS];
            int wildcard_word_indices[MAX_SEED_WORDS];
            unsigned long long idx = combo_idx;
            for (int w = 0; w < wildcard_count; w++) {
                int word_idx = (int)(idx % (unsigned long long)known_count);
                idx /= (unsigned long long)known_count;
                wildcard_indices[w]      = known_bip39_indices[word_idx];
                wildcard_word_indices[w] = word_idx;
            }

            InterlockedIncrement64(&state->processed);

            // Fast checksum prefilter.
            if (!fast_checksum_check(wildcard_indices)) continue;

            InterlockedIncrement64(&state->valid_count);

            // Build mnemonic string.
            char mnemonic[MAX_MNEMONIC_LEN];
            int mnemonic_pos = 0;
            for (int w = 0; w < SEED_WORDS_COUNT; w++) {
                if (template_is_wildcard[w]) {
                    int wc_idx   = position_to_wildcard_idx[w];
                    int word_idx = wildcard_word_indices[wc_idx];
                    int len      = known_word_lengths[word_idx];
                    memcpy(mnemonic + mnemonic_pos, known_words[word_idx], len);
                    mnemonic_pos += len;
                } else {
                    int len = template_word_lengths[w];
                    memcpy(mnemonic + mnemonic_pos, template_words[w], len);
                    mnemonic_pos += len;
                }
                if (w < SEED_WORDS_COUNT - 1) {
                    mnemonic[mnemonic_pos++] = ' ';
                }
            }
            mnemonic[mnemonic_pos] = '\0';

            // BIP39 seed -> BIP32 master key.
            uint8_t seed_bytes[64];
            pbkdf2_sha512(mnemonic, (size_t)mnemonic_pos, seed_bytes);

            uint8_t master_key[32], chain_code[32];
            bip32_master_key(seed_bytes, master_key, chain_code);

            uint8_t key[32], cc[32];
            memcpy(key, master_key, 32);
            memcpy(cc, chain_code, 32);

            // Derivation path.
            for (int p = 0; p < PATH_LEN; p++) {
                uint8_t new_key[32], new_cc[32];
                bip32_derive(key, cc, derivation_path[p], new_key, new_cc);
                memcpy(key, new_key, 32);
                memcpy(cc, new_cc, 32);
            }

            uint8_t hash160[20];
            compute_hash160(key, hash160);

            if (memcmp(hash160, state->target_hash160, 20) == 0) {
                strncpy(found_mnemonic, mnemonic, sizeof(found_mnemonic) - 1);
                found_mnemonic[sizeof(found_mnemonic) - 1] = '\0';
                seed_found_flag = 1;

                InterlockedExchange(&state->found, 1);

                FILE* f = fopen(OUT_FILE, "w");
                if (f) {
                    fprintf(f, "Seed: %s\n", mnemonic);
                    fprintf(f, "Hash160: ");
                    for (int i = 0; i < 20; i++) fprintf(f, "%02x", state->target_hash160[i]);
                    fprintf(f, "\n");
                    fclose(f);
                }

                printf("\n[!] FOUND: %s\n", mnemonic);
                printf("[!] Saved to: %s\n", OUT_FILE);
                fflush(stdout);
                return 0;
            }
        }
    }
    return 0;
}

// ===== Progress thread =====
static DWORD WINAPI progress_thread(LPVOID arg) {
    SharedState* state = (SharedState*)arg;
    time_t start = time(NULL);
    int is_rnd = (strcmp(MODE, "rnd") == 0);

    while (!state->found) {
        Sleep(1000);
        if (state->found) break;

        double elapsed   = difftime(time(NULL), start);
        uint64_t processed = state->processed;
        double speed     = elapsed > 0 ? (double)processed / elapsed : 0;

        if (is_rnd) {
            printf("\r[*] Mode: RND | Attempts: %llu | Valid: %llu | Speed: %.0f/s | Time: %.0fs",
                   (unsigned long long)processed,
                   (unsigned long long)state->valid_count,
                   speed, elapsed);
        } else {
            double pct = total_combinations
                       ? (double)processed / (double)total_combinations * 100.0
                       : 0.0;
            printf("\r[*] Mode: SEQ | Processed: %llu/%llu (%.2f%%) | Valid: %llu | Speed: %.0f/s | Time: %.0fs",
                   (unsigned long long)processed,
                   total_combinations,
                   pct,
                   (unsigned long long)state->valid_count,
                   speed, elapsed);
        }
        fflush(stdout);
    }
    return 0;
}

// ===== Self test =====
static int self_test(void) {
    print_separator();
    printf("SELF TEST\n");
    print_separator();

    const char* test_mnemonic =
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about";

    uint8_t expected_hash160[20] = {
        0xc0, 0xce, 0xbc, 0xd6, 0xc3, 0xd3, 0xca, 0x8c, 0x75, 0xdc,
        0x5e, 0xc6, 0x2e, 0xbe, 0x55, 0x33, 0x0e, 0xf9, 0x10, 0xe2
    };

    char test_words[MAX_SEED_WORDS][MAX_WORD_LEN];
    memset(test_words, 0, sizeof(test_words));

    char mnemonic_copy[512];
    strncpy(mnemonic_copy, test_mnemonic, sizeof(mnemonic_copy) - 1);
    mnemonic_copy[sizeof(mnemonic_copy) - 1] = '\0';

    char* token = strtok(mnemonic_copy, " ");
    int token_count = 0;
    while (token && token_count < SEED_WORDS_COUNT) {
        strncpy(test_words[token_count], token, MAX_WORD_LEN - 1);
        token_count++;
        token = strtok(NULL, " ");
    }

    if (!check_checksum_legacy(test_words)) { printf("FAIL: Checksum\n"); return 0; }
    printf("OK: Checksum\n");

    uint8_t seed[64];
    pbkdf2_sha512(test_mnemonic, strlen(test_mnemonic), seed);

    uint8_t master_key[32], chain_code[32];
    bip32_master_key(seed, master_key, chain_code);

    uint8_t key[32], cc[32];
    memcpy(key, master_key, 32);
    memcpy(cc, chain_code, 32);

    // Hardcode BIP84 path for self-test.
    const uint32_t bip84_path[5] = {
        0x80000000u + 84, 0x80000000u, 0x80000000u, 0, 0
    };
    for (int i = 0; i < 5; i++) {
        uint8_t new_key[32], new_cc[32];
        bip32_derive(key, cc, bip84_path[i], new_key, new_cc);
        memcpy(key, new_key, 32);
        memcpy(cc, new_cc, 32);
    }

    uint8_t hash160[20];
    compute_hash160(key, hash160);

    if (memcmp(hash160, expected_hash160, 20) == 0) {
        printf("OK: Hash160 matches\n");
    } else {
        printf("FAIL: Hash160 mismatch\n");
        return 0;
    }

    print_separator();
    printf("ALL TESTS PASSED\n");
    print_separator();
    return 1;
}

// ===== Main =====
int main(int argc, char* argv[]) {
    if (!parse_args(argc, argv)) {
        return 1;
    }

    set_derivation_path(DERIVATION_TYPE);

    print_separator();
    printf("Bitcoin Seed Finder - Template Mode (Parallel)\n");
    printf("Settings:\n");
    printf("  Threads: %d\n", NUM_THREADS);
    printf("  Seed length: %d words\n", SEED_WORDS_COUNT);
    printf("  Template file: %s\n", TPL_FILE);
    printf("  Wordlist file: %s\n", WL_FILE);
    printf("  Derivation: %s\n", get_derivation_name(DERIVATION_TYPE));
    printf("  Chunk size: %d\n", CHUNK_SIZE);
    printf("  Mode: %s\n", MODE);
    printf("  Output file: %s\n", OUT_FILE);
    printf("  Target hash160: %s\n",
           has_target_from_arg ? "from command line" : "from hash160.txt");
    print_separator();

    secp_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!secp_ctx) { printf("[!] secp256k1 init failed\n"); return 1; }

    if (load_bip39_wordlist("bip39.txt") < 0) {
        printf("[!] bip39.txt not found\n"); return 1;
    }
    printf("[*] BIP39 loaded\n");

    if (load_known_words(WL_FILE) < 0) {
        printf("[!] %s not found\n", WL_FILE); return 1;
    }
    printf("[*] Known words: %d\n", known_count);

    if (load_template(TPL_FILE) < 0) {
        printf("[!] %s not found or invalid\n", TPL_FILE); return 1;
    }

    precompute_checksum();
    printf("[*] Checksum precomputed (wildcards: %d, entropy: %d bytes)\n",
           wildcard_count, precomp.entropy_size);

    uint8_t target_hash160[20];
    if (has_target_from_arg) {
        memcpy(target_hash160, target_hash160_from_arg, 20);
        printf("[*] Target hash160: ");
        for (int i = 0; i < 20; i++) printf("%02x", target_hash160[i]);
        printf("\n");
    } else {
        if (load_target_hash160("hash160.txt", target_hash160) < 0) {
            printf("[!] hash160.txt not found or invalid (40 hex chars)\n");
            printf("[!] Use -hash <hash160> to specify target directly\n");
            return 1;
        }
        printf("[*] Target loaded from hash160.txt\n");
    }

    if (!self_test()) { printf("[!] Self test FAILED!\n"); return 1; }

    SharedState state;
    memset(&state, 0, sizeof(state));
    memcpy(state.target_hash160, target_hash160, 20);

    HANDLE progress_handle = CreateThread(NULL, 0, progress_thread, &state, 0, NULL);

    printf("[*] Starting %d threads...\n", NUM_THREADS);
    HANDLE threads[1024];
    for (int i = 0; i < NUM_THREADS; i++) {
        threads[i] = CreateThread(NULL, 0, worker_thread, &state, 0, NULL);
    }

    WaitForMultipleObjects(NUM_THREADS, threads, TRUE, INFINITE);

    state.found = 1;
    WaitForSingleObject(progress_handle, 2000);
    CloseHandle(progress_handle);

    Sleep(500);

    printf("\n\n");
    print_separator();
    if (seed_found_flag) {
        printf("[+] SEED FOUND!\n");
        printf("[+] Seed: %s\n", found_mnemonic);
        printf("[+] Saved to: %s\n", OUT_FILE);
    } else {
        printf("[-] Not found\n");
    }
    printf("[*] Processed: %llu / %llu\n",
           (unsigned long long)state.processed, total_combinations);
    printf("[*] Valid: %llu\n", (unsigned long long)state.valid_count);
    print_separator();

    for (int i = 0; i < NUM_THREADS; i++) CloseHandle(threads[i]);
    secp256k1_context_destroy(secp_ctx);

    return 0;
}