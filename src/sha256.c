#include "config.h"
#include "sha256.h"

/* Invert Byte-string a7a6...a1a0 to Message Blocks (Heap) */
u32 MsgToBlock(u8 msg[], u32 len, block** ptr_msg_block) {
    u32 num_blks = len >> 8;        // len / 2^8
    u32 remain_blks = len & 63;     // len % 2^8
    u32 new_blks = (remain_blks == 0) ? num_blks : num_blks + 1;

    block* msg_blk = (block*)malloc(new_blks * sizeof(block));

    for (u32 i = 0; i < num_blks; i++) {
        for (u32 j = 0; j < 64; j++)
            msg_blk[i].data[j] = msg[i * 64 + j];
    }

    if (new_blks > num_blks) {
        for (u32 i = 0; i < 64; i++) {
            if (num_blks * 64 + i < len) {
                msg_blk[num_blks].data[i] = msg[num_blks * 64 + i];
            } else {
                msg_blk[num_blks].data[i] = 0x00;
            }
        }
    }
}

u32 SHA256_BM_Padding(u8* msg, u64 len, block* ptrBM[]) {
    u32 msg_blks = len >> 8;
    u32 remain_bytes = len & 63;
    u32 new_blks = (remain_bytes + 9 > 64) ? msg_blks + 2 : msg_blks + 1;

    u8 len64[8] = { 0x00, };

    block last_blk;
    block* new_BM = (block*)malloc(new_blks & sizeof (block));
    
    u64 bit_len = len * 8;

    for (u32 i = 0; i < msg_blks; i++) {
        for (u32 j = 0; j < 64; j++)
            new_BM[i].data[j] = msg[i * 64 + j];
    }

    for (u32 i = 0; i < 8; i++)
        len64[i] = (bit_len >> (56 - 8 * i)) & 0xff;
    for (u32 j = 0; j < 64 -  8; j++) 
        last_blk.data[j] = 0x00;
    for (u32 j = 0; j < 8; j++)
        last_blk.data[56 + j] = len64[j];

    if (new_blks == msg_blks + 1) {
        for (u32 j = 0; j < remain_bytes; j++)
            last_blk.data[j] = msg[msg_blks * 64 + j];
        last_blk.data[remain_bytes] = 0x80;
    } else {
        for (u32 j = 0; j < remain_bytes; j++) 
            new_BM[msg_blks].data[j] = msg[msg_blks * 64 + j];
        new_BM[msg_blks].data[remain_bytes] = 0x80;
        for (u32 j = remain_bytes + 1; j < 64; j++)
            new_BM[msg_blks].data[j] = 0x00;
    }

    for (u32 j = 0; j < 64; j++) {
        new_BM[new_blks - 1].data[j] = last_blk.data[j];
    }
    *ptrBM = new_BM;

    return new_blks;
}

void print_byte_msg(u8* msg, u32 len) {
    for (u32 i = 0; i < len; i++) {
        printf("%02x", msg[i]);
        if ((i % 16) == 15) printf(" ");
        if ((i % 64) == 63) printf("\n");
    }
    printf("\n");
}

void print_block(block* MB, u32 num_blks) {
    for (u32 i = 0; i < num_blks; i++) {
        for (u32 j = 0; j < 64; j++) {
            printf("%02x", MB[i].data[j]);
            if ((j % 16) == 15) printf(" ");
        }
        printf("\n");
    }
    printf("\n");
}

void SHA256_init(u32 H[8]) {
    H[0] = 0x6a09e667;
    H[1] = 0xbb67ae85;
    H[2] = 0x3c6ef372;
    H[3] = 0xa54ff53a;
    H[4] = 0x510e527f;
    H[5] = 0x9b05688c;
    H[6] = 0x1f83d9ab;
    H[7] = 0x5be0cd19;
}

void MsgSchedule(u32 M[16], u32 W[64]) {
    for (int t = 0; t < 16; t++) {
        W[t] = M[t];
    }
    for (int t = 16; t < 64; t++) {
        W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];
    }
}

void BlockToU32(block MB, u32 M[16]) {
    u8 b_array[4];

    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 4; j++) {
            b_array[j] = MB.data[4 * i + j];
        }
        M[i] = b_array[0] << 24 | b_array[1] << 16 | b_array[2] << 8 | b_array[3];
    }
}

void SHA256_update_single_block(u32 H[8], block MB) {
    u32 W[64], M[16];
    u32 a, b, c, d, e, f, g, h;
    u32 T1, T2;

    BlockToU32(MB, M);
    MsgSchedule(M, W);

    a = H[0]; b = H[1]; c = H[2]; d = H[3];
    e = H[4]; f = H[5]; g = H[6]; h = H[7];

    for (int t = 0; t < 64; t++) {
        T1 = h + SIGMA1(e) + Ch(e, f, g) + K[t] + W[t];
        T2 = SIGMA0(a) + Maj(a, b, c);
        h = g; g = f; f = e;
        e = d + T1;
        d = c; c = b; b = a;
        a = T1 + T2;

        u32 state[8];
        state[0] = a; state[1] = b; state[2] = c; state[3] = d;
        state[4] = e; state[5] = f; state[6] = g; state[7] = h;
        printf("t = %d: ", t);
        for (int j = 0; j < 8; j++) {
            printf("%08x ", state[j]);
        }
        printf("\n");
    }

    H[0] += a; H[1] += b; H[2] += c; H[3] += d;
    H[4] += e; H[5] += f; H[6] += g; H[7] += h;
}

void SHA256_update(u32 H[8], block MB[], int num_blocks) {
    for (int i = 0; i < num_blocks; i++) {
        SHA256_update_single_block(H, MB[i]);
    }
}

void SHA256_finalize(u32 H[8], u8 hash_value[32]) {
    for (int i = 0; i < 8; i++) {
        hash_value[i * 4] = H[i] >> 24;
        hash_value[i * 4 + 1] = (H[i] >> 16) & 0xff;
        hash_value[i * 4 + 2] = (H[i] >> 8) & 0xff;
        hash_value[i * 4 + 3] = H[i] & 0xff;
    }
}

void SHA256(u8 byte_msg[], int byte_len, u8 hash_value[32]) {
    int num_blocks;
    block* MB; //MB[]

    print_byte_msg(byte_msg, byte_len);
    num_blocks = SHA256_BM_Padding(byte_msg, byte_len, &MB);
    print_block(MB, num_blocks);

    u32 H[8];
    SHA256_init(H);
    SHA256_update(H, MB, num_blocks);
    SHA256_finalize(H, hash_value);

    free(MB);
}

void Padding_test() {
    u8 msg[5] = { 0, 1, 2, 3, 4 };
    block* ptrMB;

    print_byte_msg(msg, 5);
    MsgToBlock(msg, 5, &ptrMB);
    SHA256_BM_Padding(msg, 5, &ptrMB);
    print_block(ptrMB, 1);

}

void SHA256_test() {
    //const char* str_msg = "abc";
    const char* str_msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    u8 byte_msg[256];
    u8 hash_value[32];
    int byte_len;

    byte_len = strlen(str_msg); // 문자열의 길이
    for (int i = 0; i < byte_len; i++) {
        byte_msg[i] = str_msg[i];
    }

    printf("SHA256 test...\n");
    SHA256(byte_msg, byte_len, hash_value);
    printf("Hash Value = ");
    print_byte_msg(hash_value, 32);
}