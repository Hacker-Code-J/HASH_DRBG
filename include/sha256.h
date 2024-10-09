#include "config.h"

#ifndef _SHA256_H
#define _SHA256_H

#define OUTLEN 256

typedef struct {
    u8 data[64];
} block;

static inline u32 ROR(u32 x, u32 n) {
    return (x >> n) | (x << (32 - n));
}

static inline u32 Ch(u32 x, u32 y, u32 z) {
    return (x & y) ^ (~x & z);
}

static inline u32 Maj(u32 x, u32 y, u32 z) {
    return (x & y) ^ (y & z) ^ (z & x);
}

static inline u32 SIGMA0(u32 x) {
    return ROR(x, 2) ^ ROR(x, 13) ^ ROR(x, 22);
}

static inline u32 SIGMA1(u32 x) {
    return ROR(x, 6) ^ ROR(x, 11) ^ ROR(x, 25);
}

static inline u32 sigma0(u32 x) {
    return ROR(x, 7) ^ ROR(x, 18) ^ (x >> 3);
}

static inline u32 sigma1(u32 x) {
    return ROR(x, 17) ^ ROR(x, 19) ^ (x >> 10);
}

void print_byte_msg(u8* msg, u32 len);
void print_block(block* blk, u32 num_blk);

static const u32 K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

u32 MsgToBlock(u8 msg[], u32 len, block** ptr_msg_block);
u32 SHA256_BM_Padding(u8* msg, u64 len, block* ptrBM[]);

void SHA256_init(u32 H[8]);
void MsgSchedule(u32 M[16], u32 W[64]);
void BlockToU32(block MB, u32 M[16]);

void SHA256_update_single_block(u32 H[8], block MB);
void SHA256_update(u32 H[8], block MB[], int num_blocks);
void SHA256_finalize(u32 H[8], u8 hash_value[32]);

void SHA256(u8 byte_msg[], int byte_len, u8 hash_value[32]);

void Padding_test();
void SHA256_test();

#endif  // _SHA256_H