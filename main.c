#include "rsa.h"

int main() {
    User user;
    RSAContext ctx;
    PublicKey pub;
    PrivateKey priv;
    int choice;
    int keysInitialized = 0;

    char msg[1024];
    long long cipher[1024];
    char decrypted[1024];
    int cipherLen;

    printf("1 — Registration\n2 — Log In\nChoose: ");
    scanf_s("%d", &choice);
    getchar();

    char username[50];
    printf("Enter login: ");
    fgets(username, sizeof(username), stdin);
    username[my_strcspn(username, "\n")] = '\0';
    initUser(&user, username);

    if (choice == 1) {
        registerUser(&user);
    }
    else if (choice == 2) {
        if (!loginUser(&user, &pub, &priv)) return 1;
        keysInitialized = 1;
    }
    else {
        printf("Incorrect choice.\n");
        return 1;
    }

    printf("\n--- Work with keys ---\n");
    printf("1. Generate new keys\n");
    printf("2. Load keys from file\n");
    printf("Choose: ");
    scanf_s("%d", &choice);
    getchar();

    if (choice == 1) {
        generateRSA(&ctx);
        pub = ctx.pub;
        priv = ctx.priv;
        saveKeysToFile(pub, priv, user.pubKeyFile, user.privKeyFile);
        keysInitialized = 1;
        printf("keys have been successfully generated and saved.\n");
        printf("Public key: (e = %lld, n = %lld)\n", pub.e, pub.n);
        printf("Private key: (d = %lld, n = %lld)\n", priv.d, priv.n);
    }
    else if (choice == 2) {
        if (loadKeysFromFile(&pub, &priv, user.pubKeyFile, user.privKeyFile)) {
            keysInitialized = 1;
            printf("keys have been successfully loaded.\n");
        }
        else {
            printf("key loading error.\n");
        }
    }
    else {
        printf("Incorrect choice.\n");
        return 1;
    }
    printf("\n--- RSA Μενώ ---\n");
    printf("1. Encrypt message\n");
    printf("2. Decrypt message\n");
    printf("3. Exit\n");
    do {
        
        printf("Your choice: ");
        scanf_s("%d", &choice);
        getchar();

        switch (choice) {
        case 1:
            if (!keysInitialized) {
                printf("Keys are not initialized.\n");
                break;
            }
            printf("Enter message for encryption: ");
            fgets(msg, sizeof(msg), stdin);
            msg[my_strcspn(msg, "\n")] = '\0';
            encryptText(msg, pub, cipher, &cipherLen);
            printf("Encrypted message: ");
            for (int i = 0; i < cipherLen; i++) printf("%lld ", cipher[i]);
            printf("\n");
            break;

        case 2:
            if (!keysInitialized) {
                printf("Keys are not initialized.\n");
                break;
            }
            printf("Enter the encrypted numbers separated by a space (0 at the end):\n");
            cipherLen = 0;
            while (1) {
                long long value;
                if (scanf_s("%lld", &value) != 1) {
                    printf("Enter error!\n");
                    while (getchar() != '\n');
                    break;
                }
                if (value == 0) break;
                cipher[cipherLen++] = value;
            }
            getchar();
            decryptText(cipher, cipherLen, priv, decrypted);
            printf("Decrypted message: %s\n", decrypted);
            break;

        case 3:
            printf("Exit...\n");
            break;

        default:
            printf("Incorrect choice.\n");
        }

    } while (choice != 3);

    return 0;
}

