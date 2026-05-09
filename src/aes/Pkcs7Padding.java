package aes;

import java.util.Arrays;

public class Pkcs7Padding {

    private static final int BLOCK_SIZE = 16;

    private Pkcs7Padding(){}

    public static byte[] aplicar(byte[] dado){
        if(dado == null)
            throw new IllegalArgumentException("Os dados não podem ser nulos");

        int paddingLength = BLOCK_SIZE - (dado.length % BLOCK_SIZE);

        if(paddingLength == 0)
            paddingLength = BLOCK_SIZE;

        byte[] paddedData = Arrays.copyOf(dado, dado.length + paddingLength);

        for (int i = dado.length; i < paddedData.length; i++){
            paddedData[i] = (byte) paddingLength;
        }

        return paddedData;
    }

    public static byte[] remover(byte[] paddedData){
        if (paddedData == null)
            throw new IllegalArgumentException("Os dados não podem ser nulos");

        if (paddedData.length == 0 || paddedData.length % BLOCK_SIZE != 0)
            throw new IllegalArgumentException("Dados inválidos para remoção");

        int paddingLength = paddedData[paddedData.length - 1] & 0xFF;

        if (paddingLength < 1 || paddingLength > BLOCK_SIZE)
            throw new IllegalArgumentException("Padding inválido");

        for (int i = paddedData.length - paddingLength; i < paddedData.length; i++){
            int value = paddedData[i] & 0xFF;

            if (value != paddingLength)
                throw new IllegalArgumentException("Padding inválido");
        }

        return Arrays.copyOf(paddedData, paddedData.length - paddingLength);
    }
}
