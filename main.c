#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "sha256.h"
#include "sha256.c"

//--------------SHA256 LEONARDO-----------------//


void menu() {
    printf("\n==== MENU SHA-256 ====\n");
    printf("1. Calcular hash de um arquivo\n");
    printf("2. Comparar dois arquivos\n");
    printf("3. Calcular hash de uma string\n");
    printf("0. Sair\n");
    printf("Escolha uma opcao: ");
}

int main() {
    int opcao;
    char caminho1[256], caminho2[256], input[1024];

    do {
        menu();
        scanf("%d", &opcao);
        getchar(); // limpa o '\n' do buffer

        switch (opcao) {
            case 1: {
                printf("Digite o caminho do arquivo: ");
                fgets(caminho1, sizeof(caminho1), stdin);
                caminho1[strcspn(caminho1, "\n")] = '\0';

                uint32_t tamanho;
                unsigned char* conteudo = lerArquivo(caminho1, &tamanho);

                if (!conteudo) {
                    fprintf(stderr, "Erro ao ler o arquivo.\n");
                    break;
                }

                unsigned char hash[32];
                sha256(conteudo, tamanho, hash);
                printf("Hash SHA-256:\n");
                exibirHash(hash);
                free(conteudo);
                break;
            }

            case 2: {
                printf("Digite o caminho do primeiro arquivo: ");
                fgets(caminho1, sizeof(caminho1), stdin);
                caminho1[strcspn(caminho1, "\n")] = '\0';

                printf("Digite o caminho do segundo arquivo: ");
                fgets(caminho2, sizeof(caminho2), stdin);
                caminho2[strcspn(caminho2, "\n")] = '\0';

                uint32_t tamanho1, tamanho2;
                unsigned char* conteudo1 = lerArquivo(caminho1, &tamanho1);
                unsigned char* conteudo2 = lerArquivo(caminho2, &tamanho2);

                if (!conteudo1 || !conteudo2) {
                    fprintf(stderr, "Erro ao ler um ou ambos os arquivos.\n");
                    free(conteudo1);
                    free(conteudo2);
                    break;
                }

                unsigned char hash1[32], hash2[32];
                sha256(conteudo1, tamanho1, hash1);
                sha256(conteudo2, tamanho2, hash2);

                printf("\nHash do primeiro arquivo:\n");
                exibirHash(hash1);
                printf("\nHash do segundo arquivo:\n");
                exibirHash(hash2);

                if (comparar(hash1, hash2)) {
                    printf("\nOs arquivos sao iguais.\n");
                } else {
                    printf("\nOs arquivos sao diferentes.\n");
                }

                free(conteudo1);
                free(conteudo2);
                break;
            }

            case 3: {
                printf("Digite a string para calcular o hash: ");
                fgets(input, sizeof(input), stdin);
                input[strcspn(input, "\n")] = '\0';

                unsigned char hash[32];
                sha256((unsigned char*)input, strlen(input), hash);
                printf("Hash SHA-256 da string:\n");
                exibirHash(hash);
                break;
            }

            case 0:
                printf("Encerrando o programa.\n");
                break;

            default:
                printf("Opção inválida. Tente novamente.\n");
        }
    } while (opcao != 0);

    return 0;
}