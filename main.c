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

    printf("1 � �����������\n2 � ����\n��������: ");
    scanf_s("%d", &choice);
    getchar();

    char username[50];
    printf("������� ��� ������������: ");
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
        printf("�������� �����.\n");
        return 1;
    }

    printf("\n--- ������ � ������� ---\n");
    printf("1. ������������� ����� �����\n");
    printf("2. ��������� ����� �� �����\n");
    printf("��������: ");
    scanf_s("%d", &choice);
    getchar();

    if (choice == 1) {
        generateRSA(&ctx);
        pub = ctx.pub;
        priv = ctx.priv;
        saveKeysToFile(pub, priv, user.pubKeyFile, user.privKeyFile);
        keysInitialized = 1;
        printf("����� ������� ������������� � ���������.\n");
        printf("�������� ����: (e = %lld, n = %lld)\n", pub.e, pub.n);
        printf("�������� ����: (d = %lld, n = %lld)\n", priv.d, priv.n);
    }
    else if (choice == 2) {
        if (loadKeysFromFile(&pub, &priv, user.pubKeyFile, user.privKeyFile)) {
            keysInitialized = 1;
            printf("����� ������� ���������.\n");
        }
        else {
            printf("������ �������� ������.\n");
        }
    }
    else {
        printf("�������� �����.\n");
        return 1;
    }
    printf("\n--- RSA ���� ---\n");
    printf("1. ����������� ���������\n");
    printf("2. ������������ ���������\n");
    printf("3. �����\n");
    do {
        
        printf("��� �����: ");
        scanf_s("%d", &choice);
        getchar();

        switch (choice) {
        case 1:
            if (!keysInitialized) {
                printf("����� �� ����������������.\n");
                break;
            }
            printf("������� ��������� ��� ����������: ");
            fgets(msg, sizeof(msg), stdin);
            msg[my_strcspn(msg, "\n")] = '\0';
            encryptText(msg, pub, cipher, &cipherLen);
            printf("������������� ���������: ");
            for (int i = 0; i < cipherLen; i++) printf("%lld ", cipher[i]);
            printf("\n");
            break;

        case 2:
            if (!keysInitialized) {
                printf("����� �� ����������������.\n");
                break;
            }
            printf("������� ������������� ����� ����� ������ (� ����� � 0):\n");
            cipherLen = 0;
            while (1) {
                long long value;
                if (scanf_s("%lld", &value) != 1) {
                    printf("������ �����!\n");
                    while (getchar() != '\n');
                    break;
                }
                if (value == 0) break;
                cipher[cipherLen++] = value;
            }
            getchar();
            decryptText(cipher, cipherLen, priv, decrypted);
            printf("�������������� ���������: %s\n", decrypted);
            break;

        case 3:
            printf("�����...\n");
            break;

        default:
            printf("�������� �����.\n");
        }

    } while (choice != 3);

    return 0;
}

