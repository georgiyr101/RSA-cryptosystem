#pragma once
#include <stdio.h>
#include <limits.h>
#include <locale.h>
#include <string.h>

int isPrime(long long n) {
	if (n <= 1)
		return 0;
	if (n <= 3)
		return 1;
	if (n % 2 == 0 || n % 3 == 0)
		return 0;
	for (long long i = 5; i * i <= n; i += 6) {
		if (n % i == 0 || n % (i + 2) == 0)
			return 0;
	}
	return 1;
}

long long getLongNumber() {
    long long n;
    while (1) {
        printf("Введите число: ");
        if (scanf_s("%lld", &n) == 1) {
            if (getchar() != '\n') {
                printf("Ошибка: введите одно число!\n");
                while (getchar() != '\n');
            }
            else {
                return n;
            }
        }
        else {
            printf("Ошибка: введите корректное число!\n");
            while (getchar() != '\n');
        }
    }
}

long long getPrime(const char* prompt) {
    long long num;
    do {
        printf("Введите простое число %s: ", prompt);
        num = getLongNumber();
        if (!isPrime(num)) {
            printf("Число %s не является простым. Попробуйте снова.\n", prompt);
        }
    } while (!isPrime(num));
    return num;
}

long long gcd(long long a, long long b) {
    while (b != 0) {
        long long temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

long long chooseE(long long phi) {
    long long candidates[] = {3, 5, 17, 257, 65537};
    int count = sizeof(candidates) / sizeof(candidates[0]);
    for (int i = 0; i < count; i++) {
        if (candidates[i] < phi && gcd(candidates[i], phi) == 1)
            return candidates[i];
    }

    for (long long e = 3; e < phi; e += 2) { 
        if (gcd(e, phi) == 1)
            return e;
    }

    return -1;
}

long long modInverse(long long e, long long phi) {
    long long t = 0, new_t = 1;
    long long r = phi, new_r = e;

    while (new_r != 0) {
        long long quotient = r / new_r;

        long long temp_t = t;
        t = new_t;
        new_t = temp_t - quotient * new_t;

        long long temp_r = r;
        r = new_r;
        new_r = temp_r - quotient * new_r;
    }

    if (r > 1) return -1; 
    if (t < 0) t += phi; 

    return t;
}

long long modExp(long long base, long long exp, long long mod) {
    long long result = 1;
    base = base % mod;

    while (exp > 0) {
        if (exp & 1)
            result = (result * base) % mod;

        base = (base * base) % mod;
        exp >>= 1;
    }

    return result;
}

long long encrypt(long long message, long long e, long long n) {
    return modExp(message, e, n);
}

long long decrypt(long long cipher, long long d, long long n) {
    return modExp(cipher, d, n);
}

void encryptText(const char* plaintext, long long e, long long n, long long* ciphertext, int* ciphertextLength) {
    *ciphertextLength = 0;
    for (int i = 0; plaintext[i] != '\0'; i++) {
        if (plaintext[i] >= n) {
            printf("Ошибка: символ '%c' имеет значение ASCII %d, что больше или равно n (%lld). Невозможно зашифровать.\n", plaintext[i], plaintext[i], n);
            return;
        }
        ciphertext[(*ciphertextLength)++] = encrypt(plaintext[i], e, n);
    }
}

void decryptText(const long long* ciphertext, int ciphertextLength, long long d, long long n, char* decryptedText) {
    for (int i = 0; i < ciphertextLength; i++) {
        decryptedText[i] = (char)decrypt(ciphertext[i], d, n);
    }
    decryptedText[ciphertextLength] = '\0';
}
