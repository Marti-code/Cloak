#include "rsa.h"
#include <cmath>
#include <ctime>
#include <cstdlib>
#include <stdexcept>

bool isPrime(int num) {
    if (num <= 1) return false;
    if (num <= 3) return true;
    if (num % 2 == 0 || num % 3 == 0) return false;
    for (int i = 5; i * i <= num; i += 6) {
        if (num % i == 0 || num % (i + 2) == 0) return false;
    }
    return true;
}

int gcd(int a, int b) {
    if (b == 0) {
        return a;
    }
    return gcd(b, a % b);
}

int modExp(int base, int exp, int mod) {
    int result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1)
            result = (result * base) % mod;

        exp = exp >> 1;
        base = (base * base) % mod;
    }
    return result;
}

int modInverse(int e, int r) {
    int m0 = r, t, q;
    int x0 = 0, x1 = 1;

    if (r == 1) return 0;

    while (e > 1) {
        q = e / r;
        t = r;
        r = e % r;
        e = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }

    if (x1 < 0) x1 += m0;

    return x1;
}

int generatePrime() {
    while (true) {
        int num = rand() % 100 + 100;
        if (isPrime(num)) return num;
    }
}

RSA::RSA() {
    p = generatePrime();
    q = generatePrime();
    n = p * q;
    r = (p - 1) * (q - 1);

    e = 3; // 3, 5, 7 or 65537
    while (gcd(e, r) != 1) e++;

    d = modInverse(e, r);
}

int RSA::encrypt(int message) {
    return modExp(message, e, n);
}

int RSA::decrypt(int ciphertext) {
    return modExp(ciphertext, d, n);
}

//std::vector<int> RSA::encryptString(const std::string& message) {
//    std::vector<int> encrypted;
//    for (char c : message) {
//        encrypted.push_back(encrypt(static_cast<int>(c)));
//    }
//    return encrypted;
//}
//
//std::string RSA::decryptString(const std::vector<int>& ciphertext) {
//    std::string decrypted;
//    for (int c : ciphertext) {
//        decrypted.push_back(static_cast<char>(decrypt(c)));
//    }
//    return decrypted;
//}

std::vector<int> RSA::encryptString(const std::string& message) {
    std::vector<int> encrypted;
    for (unsigned char c : message) {
        encrypted.push_back(encrypt(static_cast<int>(c)));
    }
    return encrypted;
}

std::string RSA::decryptString(const std::vector<int>& ciphertext) {
    std::string decrypted;
    for (int c : ciphertext) {
        int decrypted_char = decrypt(c);
        if (decrypted_char < 0 || decrypted_char > 255) {
            throw std::runtime_error("Takich cudow tu nie szyfrujemy");
        }
        decrypted.push_back(static_cast<unsigned char>(decrypted_char));
    }
    return decrypted;
}
