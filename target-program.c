// file: target_program.c

#include <stdio.h>
#include <stdlib.h>

#define SIZE 1000000

int main() {
    int *arr = malloc(SIZE * sizeof(int));
    if (!arr) return 1;

    for (int i = 0; i < SIZE; i++) {
        arr[i] = i * 2;
    }

    long long sum = 0;
    for (int i = 0; i < SIZE; i++) {
        sum += arr[i];
    }

    printf("Sum: %lld\n", sum);
    free(arr);
    return 0;
}

