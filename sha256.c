#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "sha256.h"

// Constantes do SHA-256 (valores da raiz cúbica dos primeiros 64 primos)
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Valores iniciais dos registradores H
uint32_t H[8] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
};

//Macros para operações
#define sigma0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define sigma1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

#define ROTR(x,n) (((x) >> (n)) | ((x) << (32-(n))))
#define CHOICE(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJORITY(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIGMA0(x) (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define SIGMA1(x) (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))

// ler arquivo
unsigned char* lerArquivo(const char* caminho, uint32_t* tamanho){
    FILE* arquivo = fopen(caminho, "rb");
    if(!arquivo){
        perror("FALHA AO ABRIR O ARQUIVO");
        return NULL;
    }

    fseek(arquivo, 0, SEEK_END);
    *tamanho = ftell(arquivo);
    rewind(arquivo);

    unsigned char* buffer = malloc(*tamanho);
    if(!buffer){
        perror("ERRO AO ALOCAR O BUFFER");
        fclose(arquivo);
        return NULL;
    }

    size_t lido = fread(buffer, 1, *tamanho, arquivo);
    if (lido != *tamanho) {
        fprintf(stderr, "Erro: Apenas %zu bytes lidos de %zu.\n", lido, *tamanho);
        free(buffer);
        fclose(arquivo);
        return NULL;
    }

    fclose(arquivo);
    return buffer;
}

// função de comparação de dois hashes
bool comparar(const uint8_t hash1[32], const uint8_t hash2[32]){
    for(int i = 0;i < 32;i++){
        if(hash1[i] != hash2[i]){
            return false;
        }
    }
    return true;
}

void exibirHash(const uint8_t hash[32]) {
    for (int i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

// Cria o message block
unsigned char* messageBlock(const unsigned char* mensagem, uint32_t tamanho_msg, uint32_t* novo_tamanho){
    uint64_t tamanho_bits = (uint64_t)tamanho_msg * 8;
    uint32_t padding = 64 - ((tamanho_msg + 1 + 8) % 64);
    if((tamanho_msg + 1 + 8) % 64 == 0) padding = 0;

    *novo_tamanho = tamanho_msg + 1 + padding + 8;
    unsigned char* bloco = (unsigned char*)calloc(*novo_tamanho, sizeof(unsigned char));

    memcpy(bloco, mensagem, tamanho_msg);
    bloco[tamanho_msg] = 0x80;

    for(int i = 0; i < 8; i++){
        bloco[*novo_tamanho - 8 + i] = (tamanho_bits >> (8 * (7 - i))) & 0xFF;
    }

    return bloco;
}

// Processa um bloco de 512 bits
void processBlock(const unsigned char* bloco, uint32_t H[8]){
    uint32_t W[64];
    createMessageSchedule(bloco, W);

    // Inicializa variáveis de trabalho
    uint32_t a = H[0];
    uint32_t b = H[1];
    uint32_t c = H[2];
    uint32_t d = H[3];
    uint32_t e = H[4];
    uint32_t f = H[5];
    uint32_t g = H[6];
    uint32_t h = H[7];

    for(int i = 0;i < 64;i++){
        uint32_t temp1 = h + SIGMA1(e) + CHOICE(e,f,g) + K[i] + W[i];
        uint32_t temp2 = SIGMA0(a) + MAJORITY(a,b,c);

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
    H[5] += f;
    H[6] += g;
    H[7] += h;
}

// Cria o message schedule
void createMessageSchedule(const unsigned char* bloco, uint32_t W[64]){
    for(int i = 0; i< 16;i++){
        W[i] =  ((uint32_t)bloco[i*4] << 24) | 
                ((uint32_t)bloco[i*4+1] << 16) | 
                ((uint32_t)bloco[i*4+2] << 8) |
                ((uint32_t)bloco[i*4+3]);
    }

    for (int i = 16; i < 64; i++) {
        W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];
    }
}

// funçao principal pra fazer a hash
void sha256(const unsigned char* mensagem, uint32_t tamanho_msg, unsigned char hash[32]){
    uint32_t novo_tamanho;
    unsigned char* blocos = messageBlock(mensagem, tamanho_msg, &novo_tamanho);

    // Inicializa os registradores
    uint32_t h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    // Processa os blocos de 512 bits
    for (uint32_t i = 0; i < novo_tamanho; i += 64) {
        processBlock(blocos + i, h);
    }

    free(blocos);

    // Escreve os 8 registradores finais no vetor de saída (hash)
    for (int i = 0; i < 8; i++) {
        hash[i*4 + 0] = (h[i] >> 24) & 0xff;
        hash[i*4 + 1] = (h[i] >> 16) & 0xff;
        hash[i*4 + 2] = (h[i] >> 8) & 0xff;
        hash[i*4 + 3] = h[i] & 0xff;
    }
}
