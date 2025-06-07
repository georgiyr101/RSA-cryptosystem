#include "rsa.h"

int main() {
    setlocale(LC_ALL, "Russian");

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

    printf("1 — Регистрация\n2 — Вход\nВыберите: ");
    scanf_s("%d", &choice);
    getchar();

    char username[50];
    printf("Введите имя пользователя: ");
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
        printf("Неверный выбор.\n");
        return 1;
    }

    printf("\n--- Работа с ключами ---\n");
    printf("1. Сгенерировать новые ключи\n");
    printf("2. Загрузить ключи из файла\n");
    printf("Выберите: ");
    scanf_s("%d", &choice);
    getchar();

    if (choice == 1) {
        generateRSA(&ctx);
        pub = ctx.pub;
        priv = ctx.priv;
        saveKeysToFile(pub, priv, user.pubKeyFile, user.privKeyFile);
        keysInitialized = 1;
        printf("Ключи успешно сгенерированы и сохранены.\n");
        printf("Открытый ключ: (e = %lld, n = %lld)\n", pub.e, pub.n);
        printf("Закрытый ключ: (d = %lld, n = %lld)\n", priv.d, priv.n);
    }
    else if (choice == 2) {
        if (loadKeysFromFile(&pub, &priv, user.pubKeyFile, user.privKeyFile)) {
            keysInitialized = 1;
            printf("Ключи успешно загружены.\n");
        }
        else {
            printf("Ошибка загрузки ключей.\n");
        }
    }
    else {
        printf("Неверный выбор.\n");
        return 1;
    }
    printf("\n--- RSA Меню ---\n");
    printf("1. Зашифровать сообщение\n");
    printf("2. Расшифровать сообщение\n");
    printf("3. Выход\n");
    do {
        
        printf("Ваш выбор: ");
        scanf_s("%d", &choice);
        getchar();

        switch (choice) {
        case 1:
            if (!keysInitialized) {
                printf("Ключи не инициализированы.\n");
                break;
            }
            printf("Введите сообщение для шифрования: ");
            fgets(msg, sizeof(msg), stdin);
            msg[my_strcspn(msg, "\n")] = '\0';
            encryptText(msg, pub, cipher, &cipherLen);
            printf("Зашифрованное сообщение: ");
            for (int i = 0; i < cipherLen; i++) printf("%lld ", cipher[i]);
            printf("\n");
            break;

        case 2:
            if (!keysInitialized) {
                printf("Ключи не инициализированы.\n");
                break;
            }
            printf("Введите зашифрованные числа через пробел (в конце — 0):\n");
            cipherLen = 0;
            while (1) {
                long long value;
                if (scanf_s("%lld", &value) != 1) {
                    printf("Ошибка ввода!\n");
                    while (getchar() != '\n');
                    break;
                }
                if (value == 0) break;
                cipher[cipherLen++] = value;
            }
            getchar();
            decryptText(cipher, cipherLen, priv, decrypted);
            printf("Расшифрованное сообщение: %s\n", decrypted);
            break;

        case 3:
            printf("Выход...\n");
            break;

        default:
            printf("Неверный выбор.\n");
        }

    } while (choice != 3);

    return 0;
}

