import aes.Aes128;
import aes.AesKeyExpansion;
import aes.ByteSequenceParser;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class AesSelfTest {

    public static void main(String[] args) {
        encryptBlockMatchesNistVector();
        decryptBlockMatchesNistVector();
        ecbEncryptionMatchesHtmlExample();
        ecbDecryptsHtmlExample();
        cbcRoundTripKeepsBinaryData();
        decimalParserAcceptsPdfKeyFormat();

        System.out.println("AesSelfTest: all tests passed");
    }

    private static void encryptBlockMatchesNistVector() {
        byte[] key = hex("000102030405060708090a0b0c0d0e0f");
        byte[] block = hex("00112233445566778899aabbccddeeff");

        byte[] encrypted = Aes128.encryptBlock(block, AesKeyExpansion.expandirChave(key));

        assertHex("69c4e0d86a7b0430d8cdb78070b4c55a", encrypted, "NIST block encryption");
    }

    private static void decryptBlockMatchesNistVector() {
        byte[] key = hex("000102030405060708090a0b0c0d0e0f");
        byte[] encrypted = hex("69c4e0d86a7b0430d8cdb78070b4c55a");

        byte[] decrypted = Aes128.decryptBlock(encrypted, AesKeyExpansion.expandirChave(key));

        assertHex("00112233445566778899aabbccddeeff", decrypted, "NIST block decryption");
    }

    private static void ecbEncryptionMatchesHtmlExample() {
        byte[] key = "ABCDEFGHIJKLMNOP".getBytes(StandardCharsets.UTF_8);
        byte[] plainText = "Vamos cifrar usando com AES!".getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = Aes128.encryptEcb(plainText, key);

        assertHex(
                "34436464baeade471d7a878b32f849525b3c67ac7065b29db2b6b265a4aa8266",
                encrypted,
                "HTML ECB encryption"
        );
    }

    private static void ecbDecryptsHtmlExample() {
        byte[] key = "ABCDEFGHIJKLMNOP".getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = hex("34436464baeade471d7a878b32f849525b3c67ac7065b29db2b6b265a4aa8266");

        byte[] decrypted = Aes128.decryptEcb(encrypted, key);

        assertArrayEquals(
                "Vamos cifrar usando com AES!".getBytes(StandardCharsets.UTF_8),
                decrypted,
                "HTML ECB decryption"
        );
    }

    private static void cbcRoundTripKeepsBinaryData() {
        byte[] key = ByteSequenceParser.parse16Bytes("20,1,94,33,199,0,48,9,31,94,112,40,59,30,100,248");
        byte[] iv = ByteSequenceParser.parse16Bytes("0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15");
        byte[] input = new byte[257];

        for (int i = 0; i < input.length; i++) {
            input[i] = (byte) i;
        }

        byte[] encrypted = Aes128.encryptCbc(input, key, iv);
        byte[] decrypted = Aes128.decryptCbc(encrypted, key, iv);

        if (encrypted.length % 16 != 0 || Arrays.equals(input, encrypted)) {
            throw new AssertionError("CBC encryption did not produce AES-sized ciphertext");
        }

        assertArrayEquals(input, decrypted, "CBC round trip");
    }

    private static void decimalParserAcceptsPdfKeyFormat() {
        byte[] key = ByteSequenceParser.parse16Bytes("20,1,94,33,199,0,48,9,31,94,112,40,59,30,100,248");

        assertHex("14015e21c70030091f5e70283b1e64f8", key, "decimal key parser");
    }

    private static byte[] hex(String value) {
        String normalized = value.replaceAll("\\s+", "");

        if (normalized.length() % 2 != 0) {
            throw new IllegalArgumentException("Invalid hexadecimal string length");
        }

        byte[] result = new byte[normalized.length() / 2];

        for (int i = 0; i < result.length; i++) {
            int index = i * 2;
            result[i] = (byte) Integer.parseInt(normalized.substring(index, index + 2), 16);
        }

        return result;
    }

    private static void assertHex(String expected, byte[] actual, String label) {
        String actualHex = toHex(actual);

        if (!expected.equals(actualHex)) {
            throw new AssertionError(label + " expected " + expected + " but got " + actualHex);
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);

        for (byte value : bytes) {
            result.append(String.format("%02x", value & 0xFF));
        }

        return result.toString();
    }

    private static void assertArrayEquals(byte[] expected, byte[] actual, String label) {
        if (!Arrays.equals(expected, actual)) {
            throw new AssertionError(label + " arrays differ");
        }
    }
}
