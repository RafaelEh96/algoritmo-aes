package aes;

import java.util.Arrays;

public final class Aes128 {

    private static final int BLOCK_SIZE = 16;
    private static final int ROUNDS = 10;

    private Aes128() {
    }

    public static byte[] cifrarBloco(byte[] block, byte[] expandedKey) {
        return encryptBlock(block, expandedKey);
    }

    public static byte[] decifrarBloco(byte[] block, byte[] expandedKey) {
        return decryptBlock(block, expandedKey);
    }

    public static byte[] cifrarEcb(byte[] data, byte[] key) {
        return encryptEcb(data, key);
    }

    public static byte[] decifrarEcb(byte[] data, byte[] key) {
        return decryptEcb(data, key);
    }

    public static byte[] cifrarCbc(byte[] data, byte[] key, byte[] iv) {
        return encryptCbc(data, key, iv);
    }

    public static byte[] decifrarCbc(byte[] data, byte[] key, byte[] iv) {
        return decryptCbc(data, key, iv);
    }

    public static byte[] encryptBlock(byte[] block, byte[] expandedKey) {
        validateBlock(block, "O bloco deve possuir exatamente 16 bytes.");
        validateExpandedKey(expandedKey);

        byte[] state = Arrays.copyOf(block, BLOCK_SIZE);

        addRoundKey(state, expandedKey, 0);

        for (int round = 1; round < ROUNDS; round++) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, expandedKey, round);
        }

        subBytes(state);
        shiftRows(state);
        addRoundKey(state, expandedKey, ROUNDS);

        return state;
    }

    public static byte[] decryptBlock(byte[] block, byte[] expandedKey) {
        validateBlock(block, "O bloco cifrado deve possuir exatamente 16 bytes.");
        validateExpandedKey(expandedKey);

        byte[] state = Arrays.copyOf(block, BLOCK_SIZE);

        addRoundKey(state, expandedKey, ROUNDS);

        for (int round = ROUNDS - 1; round >= 1; round--) {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, expandedKey, round);
            invMixColumns(state);
        }

        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, expandedKey, 0);

        return state;
    }

    public static byte[] encryptEcb(byte[] data, byte[] key) {
        byte[] expandedKey = AesKeyExpansion.expandirChave(key);
        byte[] paddedData = Pkcs7Padding.aplicar(data);
        byte[] output = new byte[paddedData.length];

        for (int offset = 0; offset < paddedData.length; offset += BLOCK_SIZE) {
            byte[] block = Arrays.copyOfRange(paddedData, offset, offset + BLOCK_SIZE);
            byte[] encryptedBlock = encryptBlock(block, expandedKey);
            System.arraycopy(encryptedBlock, 0, output, offset, BLOCK_SIZE);
        }

        return output;
    }

    public static byte[] decryptEcb(byte[] data, byte[] key) {
        validateCiphertext(data);

        byte[] expandedKey = AesKeyExpansion.expandirChave(key);
        byte[] output = new byte[data.length];

        for (int offset = 0; offset < data.length; offset += BLOCK_SIZE) {
            byte[] block = Arrays.copyOfRange(data, offset, offset + BLOCK_SIZE);
            byte[] decryptedBlock = decryptBlock(block, expandedKey);
            System.arraycopy(decryptedBlock, 0, output, offset, BLOCK_SIZE);
        }

        return Pkcs7Padding.remover(output);
    }

    public static byte[] encryptCbc(byte[] data, byte[] key, byte[] iv) {
        validateIv(iv);

        byte[] expandedKey = AesKeyExpansion.expandirChave(key);
        byte[] paddedData = Pkcs7Padding.aplicar(data);
        byte[] output = new byte[paddedData.length];
        byte[] previousBlock = Arrays.copyOf(iv, BLOCK_SIZE);

        for (int offset = 0; offset < paddedData.length; offset += BLOCK_SIZE) {
            byte[] block = Arrays.copyOfRange(paddedData, offset, offset + BLOCK_SIZE);
            xorInPlace(block, previousBlock);

            byte[] encryptedBlock = encryptBlock(block, expandedKey);
            System.arraycopy(encryptedBlock, 0, output, offset, BLOCK_SIZE);

            previousBlock = encryptedBlock;
        }

        return output;
    }

    public static byte[] decryptCbc(byte[] data, byte[] key, byte[] iv) {
        validateCiphertext(data);
        validateIv(iv);

        byte[] expandedKey = AesKeyExpansion.expandirChave(key);
        byte[] output = new byte[data.length];
        byte[] previousBlock = Arrays.copyOf(iv, BLOCK_SIZE);

        for (int offset = 0; offset < data.length; offset += BLOCK_SIZE) {
            byte[] encryptedBlock = Arrays.copyOfRange(data, offset, offset + BLOCK_SIZE);
            byte[] decryptedBlock = decryptBlock(encryptedBlock, expandedKey);
            xorInPlace(decryptedBlock, previousBlock);

            System.arraycopy(decryptedBlock, 0, output, offset, BLOCK_SIZE);
            previousBlock = encryptedBlock;
        }

        return Pkcs7Padding.remover(output);
    }

    private static void subBytes(byte[] state) {
        for (int i = 0; i < BLOCK_SIZE; i++) {
            int value = state[i] & 0xFF;
            state[i] = (byte) AesTables.SBOX[value];
        }
    }

    private static void invSubBytes(byte[] state) {
        for (int i = 0; i < BLOCK_SIZE; i++) {
            int value = state[i] & 0xFF;
            state[i] = (byte) AesTables.INV_SBOX[value];
        }
    }

    private static void shiftRows(byte[] state) {
        byte[] temp = Arrays.copyOf(state, BLOCK_SIZE);

        state[0]  = temp[0];
        state[4]  = temp[4];
        state[8]  = temp[8];
        state[12] = temp[12];

        state[1]  = temp[5];
        state[5]  = temp[9];
        state[9]  = temp[13];
        state[13] = temp[1];

        state[2]  = temp[10];
        state[6]  = temp[14];
        state[10] = temp[2];
        state[14] = temp[6];

        state[3]  = temp[15];
        state[7]  = temp[3];
        state[11] = temp[7];
        state[15] = temp[11];
    }

    private static void invShiftRows(byte[] state) {
        byte[] temp = Arrays.copyOf(state, BLOCK_SIZE);

        state[0]  = temp[0];
        state[4]  = temp[4];
        state[8]  = temp[8];
        state[12] = temp[12];

        state[1]  = temp[13];
        state[5]  = temp[1];
        state[9]  = temp[5];
        state[13] = temp[9];

        state[2]  = temp[10];
        state[6]  = temp[14];
        state[10] = temp[2];
        state[14] = temp[6];

        state[3]  = temp[7];
        state[7]  = temp[11];
        state[11] = temp[15];
        state[15] = temp[3];
    }

    private static void mixColumns(byte[] state) {
        for (int column = 0; column < 4; column++) {
            int index = column * 4;

            int s0 = state[index] & 0xFF;
            int s1 = state[index + 1] & 0xFF;
            int s2 = state[index + 2] & 0xFF;
            int s3 = state[index + 3] & 0xFF;

            state[index]     = (byte) (gmul(s0, 2) ^ gmul(s1, 3) ^ s2 ^ s3);
            state[index + 1] = (byte) (s0 ^ gmul(s1, 2) ^ gmul(s2, 3) ^ s3);
            state[index + 2] = (byte) (s0 ^ s1 ^ gmul(s2, 2) ^ gmul(s3, 3));
            state[index + 3] = (byte) (gmul(s0, 3) ^ s1 ^ s2 ^ gmul(s3, 2));
        }
    }

    private static void invMixColumns(byte[] state) {
        for (int column = 0; column < 4; column++) {
            int index = column * 4;

            int s0 = state[index] & 0xFF;
            int s1 = state[index + 1] & 0xFF;
            int s2 = state[index + 2] & 0xFF;
            int s3 = state[index + 3] & 0xFF;

            state[index]     = (byte) (gmul(s0, 14) ^ gmul(s1, 11) ^ gmul(s2, 13) ^ gmul(s3, 9));
            state[index + 1] = (byte) (gmul(s0, 9) ^ gmul(s1, 14) ^ gmul(s2, 11) ^ gmul(s3, 13));
            state[index + 2] = (byte) (gmul(s0, 13) ^ gmul(s1, 9) ^ gmul(s2, 14) ^ gmul(s3, 11));
            state[index + 3] = (byte) (gmul(s0, 11) ^ gmul(s1, 13) ^ gmul(s2, 9) ^ gmul(s3, 14));
        }
    }

    private static int gmul(int value, int multiplier) {
        int result = 0;
        int a = value;
        int b = multiplier;

        while (b > 0) {
            if ((b & 1) != 0) {
                result ^= a;
            }

            boolean highBitSet = (a & 0x80) != 0;
            a = (a << 1) & 0xFF;

            if (highBitSet) {
                a ^= 0x1B;
            }

            b >>= 1;
        }

        return result & 0xFF;
    }

    private static void addRoundKey(byte[] state, byte[] expandedKey, int round) {
        int start = round * BLOCK_SIZE;

        for (int i = 0; i < BLOCK_SIZE; i++) {
            state[i] = (byte) ((state[i] & 0xFF) ^ (expandedKey[start + i] & 0xFF));
        }
    }

    private static void xorInPlace(byte[] target, byte[] mask) {
        for (int i = 0; i < BLOCK_SIZE; i++) {
            target[i] = (byte) ((target[i] & 0xFF) ^ (mask[i] & 0xFF));
        }
    }

    private static void validateBlock(byte[] block, String message) {
        if (block == null || block.length != BLOCK_SIZE) {
            throw new IllegalArgumentException(message);
        }
    }

    private static void validateExpandedKey(byte[] expandedKey) {
        if (expandedKey == null || expandedKey.length != 176) {
            throw new IllegalArgumentException("A chave expandida deve possuir exatamente 176 bytes.");
        }
    }

    private static void validateCiphertext(byte[] data) {
        if (data == null || data.length == 0 || data.length % BLOCK_SIZE != 0) {
            throw new IllegalArgumentException("Os dados cifrados devem ter tamanho multiplo de 16 bytes.");
        }
    }

    private static void validateIv(byte[] iv) {
        if (iv == null || iv.length != BLOCK_SIZE) {
            throw new IllegalArgumentException("O IV deve possuir exatamente 16 bytes.");
        }
    }
}
