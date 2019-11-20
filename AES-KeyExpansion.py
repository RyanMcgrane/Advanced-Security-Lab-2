#!/usr/bin/env python
# TODO: 1. Write Rcon, Sbox & InvSbox generators instead of using tables; (Learning purpose)
#    2. Implement several mode of operations http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation
#    3. Find a better implementation of KeyExpansion(), ShiftRows() and MixColumns()
#    4. Implement file encryption
#    5. Implement block device encryption
#    6. Implement argument handling for the file/block device encryption and test cases from the FIPS-197.pdf file
#
# ----------------------------------------------------------------------

import sys, traceback

############################## SubBytes ##############################
# http://en.wikipedia.org/wiki/Rijndael_S-box
Sbox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]

def SubBytes(state):
    for i in range(IOBlockSize): state[i] = Sbox[state[i]]
    return state


def SubWord(word): return Sbox[word]


############################## ShiftRows ##############################
# state        return state
# 0 4  8 12     0  4 8 12
# 1 5  9 13    13  1 5  9
# 2 6 10 14    10 14 2  6
# 3 7 11 15    7  11 15 3
#
# state before:    0  1  2 3 4 5  6  7 8 9 10 11 12 13 14 15
# state after:    0 13 10 7 4 1 14 11 8 5  2 15 12  9  6 3

def ShiftRows(state):
    tmp13 = state[13]
    state[13] = state[1]
    state[1] = state[5]
    state[5] = state[9]
    state[9] = tmp13

    tmp15 = state[15]
    state[15] = state[11]
    state[11] = state[7]
    state[7] = state[3]
    state[3] = tmp15

    tmp2 = state[2]
    state[2] = state[10]
    state[10] = tmp2

    tmp6 = state[6]
    state[6] = state[14]
    state[14] = tmp6

    return state

############################## MixColumns ##############################
def MixColumns(state):
    block = []
    while len(block) < IOBlockSize: block.append(0)
    k = 0
    while k <= IOBlockSize - 4:
        block[k] = GF(2, state[k]) ^ GF(3, state[k + 1]) ^ GF(1, state[k + 2]) ^ GF(1, state[k + 3])
        block[k + 1] = GF(1, state[k]) ^ GF(2, state[k + 1]) ^ GF(3, state[k + 2]) ^ GF(1, state[k + 3])
        block[k + 2] = GF(1, state[k]) ^ GF(1, state[k + 1]) ^ GF(2, state[k + 2]) ^ GF(3, state[k + 3])
        block[k + 3] = GF(3, state[k]) ^ GF(1, state[k + 1]) ^ GF(1, state[k + 2]) ^ GF(2, state[k + 3])
        k += 4
    return block


# Galois multiplication in GF(2^8) of 8 bit characters a and b
def GF(a, b):
    r = 0
    for times in range(8):
        if (b & 1) == 1: r = r ^ a
        if r > 0x100: r = r ^ 0x100
        # keep r 8 bit
        hi_bit_set = (a & 0x80)
        a = a << 1
        if a > 0x100:
            # keep a 8 bit
            a = a ^ 0x100
        if hi_bit_set == 0x80:
            a = a ^ 0x1b
        if a > 0x100:
            # keep a 8 bit
            a = a ^ 0x100
        b = b >> 1
        if b > 0x100:
            # keep b 8 bit
            b = b ^ 0x100
    return r


############################## AddRoundKey ##############################
def AddRoundKey(state, RoundKey):
    for i in range(IOBlockSize):
        if i < len(RoundKey): state[i] = state[i] ^ RoundKey[i]
    return state


def NextRoundKey(RoundKeyArray, NextRoundKeyPointer):
    NextRoundKey = []
    k = 0

    while len(NextRoundKey) < IOBlockSize: NextRoundKey.append(0)
    for i in range(4):
        NextRoundKey[i * 4] = RoundKeyArray[NextRoundKeyPointer + k]
        NextRoundKey[i * 4 + 1] = RoundKeyArray[NextRoundKeyPointer + k + 1]
        NextRoundKey[i * 4 + 2] = RoundKeyArray[NextRoundKeyPointer + k + 2]
        NextRoundKey[i * 4 + 3] = RoundKeyArray[NextRoundKeyPointer + k + 3]
        k += 4  # next column
    return NextRoundKey


############################## KEY SCHEDULE ##############################
Rcon = [
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d,
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab,
    0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
    0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25,
    0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01,
    0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
    0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa,
    0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
    0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02,
    0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f,
    0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
    0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33,
    0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb]


def getRconValue(num): return Rcon[num]


# RotWord(aabbccdd) = bbccddaa
#
# Before:
# aa cc
# bb dd
#
# After:
# bb dd
# cc aa
def RotWord(word):
    temp = word[0]
    for i in range(3): word[i] = word[i + 1]
    word[3] = temp
    return word


#  Nk = 8 for 256-bit key, 6 for 192-bit key,  4 for 128-bit key
#  32/4 = 8, 24/4 = 6, 16/4 = 4
#  expandedKeySize = IOBlockSize*(nbrRounds+1)
#  expandedKeySize = Nb(Nr+1)
#  Expands 128,192,256 key into an 176,208,240 bytes key
def KeyExpansion(CipherKeyArray, CipherKeySize, expandedKeySize):
    i = 0
    rconIteration = 1
    w = [0, 0, 0, 0]

    expandedKey = []
    while len(expandedKey) < expandedKeySize: expandedKey.append(0)

    for j in range(CipherKeySize): expandedKey[j] = CipherKeyArray[j]

    i += CipherKeySize
    while i < expandedKeySize:
        for k in range(4): w[k] = expandedKey[(i - 4) + k]

        # Every 16,24,32 bytes
        if i % CipherKeySize == 0:
            w = RotWord(w)
            for r in range(4): w[r] = SubWord(w[r])
            w[0] = w[0] ^ getRconValue(rconIteration)
            rconIteration += 1

        # For 256-bit keys, we add an extra Sbox to the calculation
        if CipherKeySize == 256 / 8 and (i % CipherKeySize) == IOBlockSize:
            for e in range(4): w[e] = SubWord(w[e])

        for m in range(4):
            expandedKey[i] = expandedKey[i - CipherKeySize] ^ w[m]
            i += 1

    return expandedKey


############################## Cipher ##############################
def AESCipher(PlaintextArray, CipherKeyArray, CipherKeySize):
    if CipherKeySize == 128 / 8:
        nbrRounds = 10
    elif CipherKeySize == 192 / 8:
        nbrRounds = 12
    elif CipherKeySize == 256 / 8:
        nbrRounds = 14

    state = []
    while len(state) < CipherKeySize: state.append(0)
    for i in range(CipherKeySize):
        if i < len(PlaintextArray): state[i] = PlaintextArray[i]

    RoundKeyArraySize = IOBlockSize * (nbrRounds + 1)
    RoundKeyArray = KeyExpansion(CipherKeyArray, CipherKeySize, RoundKeyArraySize)

    state = AddRoundKey(state, CipherKeyArray)

    i = 0
    while i < nbrRounds:
        i += 1
        state = SubBytes(state)
        state = ShiftRows(state)
        if i < nbrRounds: state = MixColumns(state)  # Do not MixColumns in the last Round.
        state = AddRoundKey(state, NextRoundKey(RoundKeyArray, IOBlockSize * i))

    return state


# ========================= MAIN =============================
def PrintBox(arr, len):
    n = 0
    m = 0
    while n < 4:
        while m <= len - 4:
            print('%0.2X' % arr[n + m]),
            m += 4
        print("\t")
        m = 0
        n += 1


isKeyExpansionTEST = 0  # Test Cases from "Appendix A - Key Expansion Examples", page 27-32 http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
isCipherExampleTEST = 1  # Test Cases from "Appendix B - Cipher Example", pages 33-34 http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
isExampleVectorTEST = 0  # Test Cases from "Appendix C - Example Vectors", page 35-46 http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf

isStringMode = 0  # Print Input & Output in String mode

# Global structure of input block sizes
IOBlockSize = 16  # 128-bit input


def main():
    #    CipherKeySize = 128/8
    #    CipherKeySize = 192/8
    CipherKeySize = 256 / 8

    try:

        print("\n=============== START ===================\n")
        PlaintextString = "secret message!"
        CipherKeyString = "password is here"

        PlaintextArray = []
        CipherKeyArray = []
        while len(PlaintextArray) < IOBlockSize: PlaintextArray.append(0)
        while len(CipherKeyArray) < CipherKeySize: CipherKeyArray.append(0)

        for i in range(len(list(PlaintextString))): PlaintextArray[i] = int(list(PlaintextString)[i].encode("hex"),
                                                                            16)  # 16 stands for HEX
        for i in range(len(list(CipherKeyString))): CipherKeyArray[i] = int(list(CipherKeyString)[i].encode("hex"),
                                                                            16)  # 16 stands for HEX

    except KeyboardInterrupt:
        print("Shutdown requested... exiting")
        return 1
    except Exception:
        traceback.print_exc(file=sys.stdout)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
