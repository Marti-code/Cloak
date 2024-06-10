#pragma once

#include <iostream>
#include <vector>
#include <string>

#include "API.h"

bool isPrime(int num);
int gcd(int a, int b);
int modExp(int base, int exp, int mod);
int modInverse(int a, int m);
int generatePrime();

class EXPORT_API RSA {
public:
    RSA();
    int encrypt(int message);
    int decrypt(int ciphertext);
    std::vector<int> encryptString(const std::string& message);
    std::string decryptString(const std::vector<int>& ciphertext);

private:
    int p, q, n, r, e, d;
};
