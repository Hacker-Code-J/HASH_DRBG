#include "config.h"
#include "sha256.h"

int main(int argc, char* argv[]) {
    printf("Test\n");

    Padding_test();
    SHA256_test();

    return 0;
}