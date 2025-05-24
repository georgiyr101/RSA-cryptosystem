#include "rsa.h"

int main() {

	setlocale(LC_ALL, "russian");
	long long p = getPrime("p");
	long long q = getPrime("q");
	printf("�� ����� ��� ������� �����: p = %lld, q = %lld\n", p, q);
	long long n = p * q;
	long long phi = (p - 1) * (q - 1);
	long long e = chooseE(phi);
	if (e == -1) {
		printf("������: �� ������� ������� e\n");
	}
	else {
		printf("��������� �������� e: %lld\n", e);
	}
	long long d = modInverse(e, phi);
	if (d == -1) {
		printf("������: �� ������� ����� �������� ������� ��� e\n");
	}
	else {
		printf("�������� ���������� d: %lld\n", d);
	}
	printf("\n--- ����� RSA ---\n");
	printf("�������� ���� (e, n): (%lld, %lld)\n", e, n);
	printf("�������� ���� (d, n): (%lld, %lld)\n", d, n);

	long long message = getLongNumber(); 
	long long cipher = encrypt(message, e, n);
	printf("������������� ���������: %lld\n", cipher);
	long long decrypted = decrypt(cipher, d, n);
	printf("�������������� ���������: %lld\n", decrypted);

	char plaintext[256];
	printf("������� ����� ��� ����������: ");
	fgets(plaintext, sizeof(plaintext), stdin);
	plaintext[strcspn(plaintext, "\n")] = 0; 

	int ciphertextLength = 0;
	long long ciphertext[256];
	encryptText(plaintext, e, n, ciphertext, &ciphertextLength);

	if (ciphertextLength > 0) {
		printf("������������� ��������� (�����): ");
		for (int i = 0; i < ciphertextLength; i++) {
			printf("%lld ", ciphertext[i]);
		}
		printf("\n");

		char decryptedText[256];
		decryptText(ciphertext, ciphertextLength, d, n, decryptedText);
		printf("�������������� ���������: %s\n", decryptedText);
	}
	return 0;
}


