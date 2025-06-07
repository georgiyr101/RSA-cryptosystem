#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

typedef struct {
    long long e;
    long long n;
} PublicKey;

typedef struct {
    long long d;
    long long n;
} PrivateKey;

typedef struct {
    long long p, q, phi;
    PublicKey pub;
    PrivateKey priv;
} RSAContext;

typedef struct {
    char username[50];
    char pubKeyFile[64];
    char privKeyFile[64];
    char passwordFile[64];
} User;

int my_strcspn(const char* str, const char* reject) {
    int i, j;
    for (i = 0; str[i] != '\0'; ++i) {
        for (j = 0; reject[j] != '\0'; ++j) {
            if (str[i] == reject[j])
                return i;
        }
    }
    return i; 
}

char* my_strncpy(char* dest, const char* src, int n) {
    int i = 0;
    for (; i < n && src[i] != '\0'; i++) {
        dest[i] = src[i];
    }
    for (; i < n; i++) {
        dest[i] = '\0';
    }
    return dest;
}

int isPrime(long long n) {
    if (n <= 1) return 0;
    if (n <= 3) return 1;
    if (n % 2 == 0 || n % 3 == 0) return 0;
    for (long long i = 5; i * i <= n; i += 6)
        if (n % i == 0 || n % (i + 2) == 0)
            return 0;
    return 1;
}

long long getLongNumber() {
    long long n;
    while (1) {
        printf("Enter number: ");
        if (scanf_s("%lld", &n) == 1) {
            if (getchar() != '\n') {
                printf("Error!\n");
                while (getchar() != '\n');
            }
            else return n;
        }
        else {
            printf("Error!\n");
            while (getchar() != '\n');
        }
    }
}

long long getPrime(const char* prompt) {
    long long num;
    do {
        printf("Enter prime number %s: ", prompt);
        num = getLongNumber();
        if (!isPrime(num))
            printf("Number %s is not prime. Try again.\n", prompt);
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
    long long candidates[] = { 3, 5, 17, 257, 65537 };
    int count = sizeof(candidates) / sizeof(candidates[0]);
    for (int i = 0; i < count; i++)
        if (candidates[i] < phi && gcd(candidates[i], phi) == 1)
            return candidates[i];

    for (long long e = 3; e < phi; e += 2)
        if (gcd(e, phi) == 1)
            return e;

    return -1;
}

long long modInverse(long long e, long long phi) {
    long long t = 0, new_t = 1, r = phi, new_r = e;
    while (new_r != 0) {
        long long q = r / new_r;
        long long temp = t; t = new_t; new_t = temp - q * new_t;
        temp = r; r = new_r; new_r = temp - q * new_r;
    }
    if (r > 1) return -1;
    if (t < 0) t += phi;
    return t;
}

long long modExp(long long base, long long exp, long long mod) {
    long long result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1)
            result = (result * base) % mod;
        exp = exp / 2;
        base = (base * base) % mod;
    }
    return result;
}

void generateRSA(RSAContext* ctx) {
    ctx->p = getPrime("p");
    ctx->q = getPrime("q");
    ctx->pub.n = ctx->p * ctx->q;
    ctx->phi = (ctx->p - 1) * (ctx->q - 1);
    ctx->pub.e = chooseE(ctx->phi);
    ctx->priv.d = modInverse(ctx->pub.e, ctx->phi);
    ctx->priv.n = ctx->pub.n;
}

void encryptText(const char* plaintext, PublicKey key, long long* ciphertext, int* ciphertextLength) {
    *ciphertextLength = 0;
    for (int i = 0; plaintext[i] != '\0'; i++) {
        ciphertext[(*ciphertextLength)++] = modExp((unsigned char)plaintext[i], key.e, key.n);
    }
}

void decryptText(const long long* ciphertext, int ciphertextLength, PrivateKey key, char* decryptedText) {
    for (int i = 0; i < ciphertextLength; i++)
        decryptedText[i] = (char)modExp(ciphertext[i], key.d, key.n);
    decryptedText[ciphertextLength] = '\0';
}

int saveKeysToFile(PublicKey pub, PrivateKey priv, const char* pubFile, const char* privFile) {
    FILE* fpub = fopen(pubFile, "w");
    FILE* fpriv = fopen(privFile, "w");
    if (!fpub || !fpriv) return 0;

    fprintf(fpub, "%lld %lld\n", pub.e, pub.n);
    fprintf(fpriv, "%lld %lld\n", priv.d, priv.n);
    fclose(fpub);
    fclose(fpriv);
    return 1;
}

int loadKeysFromFile(PublicKey* pub, PrivateKey* priv, const char* pubFile, const char* privFile) {
    FILE* fpub = fopen(pubFile, "r");
    FILE* fpriv = fopen(privFile, "r");
    if (!fpub || !fpriv) return 0;

    fscanf(fpub, "%lld %lld", &pub->e, &pub->n);
    fscanf(fpriv, "%lld %lld", &priv->d, &priv->n);
    fclose(fpub);
    fclose(fpriv);
    return 1;
}

unsigned long simpleHash(const char* str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;  
    return hash;
}

void initUser(User* user, const char* username) {
    strncpy(user->username, username, sizeof(user->username));
    snprintf(user->pubKeyFile, sizeof(user->pubKeyFile), "%s_pub.key", username);
    snprintf(user->privKeyFile, sizeof(user->privKeyFile), "%s_priv.key", username);
    snprintf(user->passwordFile, sizeof(user->passwordFile), "%s.pwd", username);
}

void registerUser(User* user) {
    FILE* f = fopen(user->passwordFile, "r");
    if (f) {
        fclose(f);
        printf("Пользователь с таким именем уже существует.\n");
        exit(1);
    }

    char password[50];
    printf("Придумайте пароль: ");
    fgets(password, sizeof(password), stdin);
    password[my_strcspn(password, "\n")] = '\0';

    unsigned long hash = simpleHash(password);
    f = fopen(user->passwordFile, "w");
    fprintf(f, "%lu", hash);
    fclose(f);
    printf("Пользователь зарегистрирован.\n");
}

int loginUser(User* user, PublicKey* pub, PrivateKey* priv) {
    FILE* f = fopen(user->passwordFile, "r");
    if (!f) {
        printf("Пользователь не найден.\n");
        return 0;
    }

    unsigned long storedHash;
    fscanf(f, "%lu", &storedHash);
    fclose(f);

    char password[50];
    printf("Введите пароль: ");
    fgets(password, sizeof(password), stdin);
    password[my_strcspn(password, "\n")] = '\0';

    if (simpleHash(password) != storedHash) {
        printf("Неверный пароль.\n");
        return 0;
    }

    if (!loadKeysFromFile(pub, priv, user->pubKeyFile, user->privKeyFile)) {
        printf("Ключи не найдены или повреждены.\n");
        return 0;
    }

    printf("Успешный вход.\n");
    return 1;
}
