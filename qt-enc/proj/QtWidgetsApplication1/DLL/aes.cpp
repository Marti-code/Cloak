#include "aes.h"

AES128::AES128(const vector<uint8_t>& key) {
    KeyExpansion(key);
}

void AES128::EncryptBlock(vector<uint8_t>& block) {
    AddRoundKey(block, 0);

    for (int round = 1; round <= 9; ++round) {
        SubBytes(block);
        ShiftRows(block);
        MixColumns(block);
        AddRoundKey(block, round);
    }

    SubBytes(block);
    ShiftRows(block);
    AddRoundKey(block, 10);
}

void AES128::DecryptBlock(vector<uint8_t>& block) {
    AddRoundKey(block, 10);

    for (int round = 9; round >= 1; --round) {
        InvShiftRows(block);
        InvSubBytes(block);
        AddRoundKey(block, round);
        InvMixColumns(block);
    }

    InvShiftRows(block);
    InvSubBytes(block);
    AddRoundKey(block, 0);
}

vector<uint8_t> AES128::EncryptMessage(const string& message) {
    vector<uint8_t> paddedMessage = PadMessage(message);
    for (size_t i = 0; i < paddedMessage.size(); i += 16) {
        vector<uint8_t> block(paddedMessage.begin() + i, paddedMessage.begin() + i + 16);
        EncryptBlock(block);
        copy(block.begin(), block.end(), paddedMessage.begin() + i);
    }
    return paddedMessage;
}

string AES128::DecryptMessage(const vector<uint8_t>& encryptedMessage) {
    vector<uint8_t> decryptedMessage = encryptedMessage;
    for (size_t i = 0; i < decryptedMessage.size(); i += 16) {
        vector<uint8_t> block(decryptedMessage.begin() + i, decryptedMessage.begin() + i + 16);
        DecryptBlock(block);
        copy(block.begin(), block.end(), decryptedMessage.begin() + i);
    }
    return UnpadMessage(decryptedMessage);
}

void AES128::KeyExpansion(const vector<uint8_t>& key) {
    RoundKeys.resize(44, vector<uint8_t>(4));

    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            RoundKeys[i][j] = key[i * 4 + j];
        }
    }

    for (int i = 4; i < 44; ++i) {
        vector<uint8_t> temp = RoundKeys[i - 1];

        if (i % 4 == 0) {
            RotWord(temp);
            SubWord(temp);
            temp[0] ^= Rcon[i / 4 - 1];
        }

        for (int j = 0; j < 4; ++j) {
            RoundKeys[i][j] = RoundKeys[i - 4][j] ^ temp[j];
        }
    }
}

void AES128::AddRoundKey(vector<uint8_t>& state, int round) {
    for (int i = 0; i < 16; ++i) {
        state[i] ^= RoundKeys[round * 4 + i / 4][i % 4];
    }
}

void AES128::SubBytes(vector<uint8_t>& state) {
    for (int i = 0; i < 16; ++i) {
        state[i] = SBox[state[i]];
    }
}

void AES128::InvSubBytes(vector<uint8_t>& state) {
    for (int i = 0; i < 16; ++i) {
        state[i] = InvSBox[state[i]];
    }
}

void AES128::ShiftRows(vector<uint8_t>& state) {
    vector<uint8_t> temp(16);

    for (int i = 0; i < 16; ++i) {
        temp[i] = state[i];
    }

    state[0] = temp[0];
    state[1] = temp[5];
    state[2] = temp[10];
    state[3] = temp[15];

    state[4] = temp[4];
    state[5] = temp[9];
    state[6] = temp[14];
    state[7] = temp[3];

    state[8] = temp[8];
    state[9] = temp[13];
    state[10] = temp[2];
    state[11] = temp[7];

    state[12] = temp[12];
    state[13] = temp[1];
    state[14] = temp[6];
    state[15] = temp[11];
}

void AES128::InvShiftRows(vector<uint8_t>& state) {
    vector<uint8_t> temp(16);

    for (int i = 0; i < 16; ++i) {
        temp[i] = state[i];
    }

    state[0] = temp[0];
    state[1] = temp[13];
    state[2] = temp[10];
    state[3] = temp[7];

    state[4] = temp[4];
    state[5] = temp[1];
    state[6] = temp[14];
    state[7] = temp[11];

    state[8] = temp[8];
    state[9] = temp[5];
    state[10] = temp[2];
    state[11] = temp[15];

    state[12] = temp[12];
    state[13] = temp[9];
    state[14] = temp[6];
    state[15] = temp[3];
}

void AES128::MixColumns(vector<uint8_t>& state) {
    vector<uint8_t> temp(16);

    for (int i = 0; i < 16; ++i) {
        temp[i] = state[i];
    }

    for (int i = 0; i < 4; ++i) {
        state[i * 4 + 0] = Multiply(0x02, temp[i * 4 + 0]) ^ Multiply(0x03, temp[i * 4 + 1]) ^ temp[i * 4 + 2] ^ temp[i * 4 + 3];
        state[i * 4 + 1] = temp[i * 4 + 0] ^ Multiply(0x02, temp[i * 4 + 1]) ^ Multiply(0x03, temp[i * 4 + 2]) ^ temp[i * 4 + 3];
        state[i * 4 + 2] = temp[i * 4 + 0] ^ temp[i * 4 + 1] ^ Multiply(0x02, temp[i * 4 + 2]) ^ Multiply(0x03, temp[i * 4 + 3]);
        state[i * 4 + 3] = Multiply(0x03, temp[i * 4 + 0]) ^ temp[i * 4 + 1] ^ temp[i * 4 + 2] ^ Multiply(0x02, temp[i * 4 + 3]);
    }
}

void AES128::InvMixColumns(vector<uint8_t>& state) {
    vector<uint8_t> temp(16);

    for (int i = 0; i < 16; ++i) {
        temp[i] = state[i];
    }

    for (int i = 0; i < 4; ++i) {
        state[i * 4 + 0] = Multiply(0x0E, temp[i * 4 + 0]) ^ Multiply(0x0B, temp[i * 4 + 1]) ^ Multiply(0x0D, temp[i * 4 + 2]) ^ Multiply(0x09, temp[i * 4 + 3]);
        state[i * 4 + 1] = Multiply(0x09, temp[i * 4 + 0]) ^ Multiply(0x0E, temp[i * 4 + 1]) ^ Multiply(0x0B, temp[i * 4 + 2]) ^ Multiply(0x0D, temp[i * 4 + 3]);
        state[i * 4 + 2] = Multiply(0x0D, temp[i * 4 + 0]) ^ Multiply(0x09, temp[i * 4 + 1]) ^ Multiply(0x0E, temp[i * 4 + 2]) ^ Multiply(0x0B, temp[i * 4 + 3]);
        state[i * 4 + 3] = Multiply(0x0B, temp[i * 4 + 0]) ^ Multiply(0x0D, temp[i * 4 + 1]) ^ Multiply(0x09, temp[i * 4 + 2]) ^ Multiply(0x0E, temp[i * 4 + 3]);
    }
}

uint8_t AES128::Multiply(uint8_t x, uint8_t y) {
    uint8_t result = 0;
    uint8_t temp = x;

    for (int i = 0; i < 8; ++i) {
        if (y & 0x01) {
            result ^= temp;
        }

        bool carry = temp & 0x80;
        temp <<= 1;
        if (carry) {
            temp ^= 0x1B;
        }
        y >>= 1;
    }

    return result;
}

void AES128::RotWord(vector<uint8_t>& word) {
    uint8_t temp = word[0];
    for (int i = 0; i < 3; ++i) {
        word[i] = word[i + 1];
    }
    word[3] = temp;
}

void AES128::SubWord(vector<uint8_t>& word) {
    for (int i = 0; i < 4; ++i) {
        word[i] = SBox[word[i]];
    }
}

vector<uint8_t> AES128::PadMessage(const string& message) {
    vector<uint8_t> paddedMessage(message.begin(), message.end());
    size_t padLength = 16 - (paddedMessage.size() % 16);
    paddedMessage.insert(paddedMessage.end(), padLength, static_cast<uint8_t>(padLength));
    return paddedMessage;
}

string AES128::UnpadMessage(const vector<uint8_t>& message) {
    uint8_t padLength = message.back();
    return string(message.begin(), message.end() - padLength);
}
