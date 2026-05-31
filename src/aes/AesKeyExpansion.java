package aes;

public class AesKeyExpansion {

    private static final int KEY_SIZE = 16;
    private static final int EXPANDED_KEY_SIZE = 176;
    private static final int WORD_SIZE = 4;

    public AesKeyExpansion() {
    }

    public static byte[] expandirChave(byte[] chave){
        if (chave == null || chave.length != KEY_SIZE)
            throw new IllegalArgumentException("A chave deve possuir exatamente 16 bytes");

        byte[] expandedKey = new byte[EXPANDED_KEY_SIZE];

        System.arraycopy(chave,0, expandedKey, 0, KEY_SIZE);

        int bytesGerados = KEY_SIZE;
        int interacaoRcon = 1;

        byte[] temp = new byte[WORD_SIZE];

        while (bytesGerados < EXPANDED_KEY_SIZE){

            System.arraycopy(expandedKey, bytesGerados - WORD_SIZE, temp, 0, WORD_SIZE);

            if(bytesGerados % KEY_SIZE == 0){
                rotacionarPalavra(temp);
                subPalavra(temp);
                temp[0] = (byte) ((temp[0] & 0xFF) ^ AesTables.RCON[interacaoRcon]);
                interacaoRcon++;
            }

            for (int i = 0; i < WORD_SIZE; i++){
                int previousKyByte = expandedKey[bytesGerados - KEY_SIZE] & 0xFF;
                int tempByte = temp[i] & 0xFF;

                expandedKey[bytesGerados] = (byte) (previousKyByte ^ tempByte);
                bytesGerados++;
            }
        }

        return expandedKey;
    }

    private static void rotacionarPalavra(byte[] palavra){
        byte primeira = palavra[0];

        palavra[0] = palavra[1];
        palavra[1] = palavra[2];
        palavra[2] = palavra[3];
        palavra[3] = primeira;
    }

    private static void subPalavra(byte[] palavra){
        for (int i = 0; i < palavra.length; i++){
            int temp = palavra[i] & 0xFF;
            palavra[i] = (byte) AesTables.SBOX[temp];
        }
    }
}
