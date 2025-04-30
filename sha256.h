#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stdbool.h>

unsigned char* messageBlock(const unsigned char* mensagem, uint32_t tamanho_msg, uint32_t* novoTamanho);

void createMessageSchedule(const unsigned char* bloco, uint32_t W[64]);

void processBlock(const unsigned char* bloco, uint32_t H[8]);

void sha256(const unsigned char* mensagem, uint32_t tamanho_msg, unsigned char hash[32]);

unsigned char* lerArquivo(const char* caminho, uint32_t* tamanho);

bool comparar(const uint8_t hash1[32], const uint8_t hash2[32]);

void exibirHash(const uint8_t hash[32]);

#endif