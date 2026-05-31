package aes;

public final class ByteSequenceParser {

    private static final int EXPECTED_SIZE = 16;

    private ByteSequenceParser() {
    }

    public static byte[] parse16Bytes(String input) {
        if (input == null) {
            throw new IllegalArgumentException("A sequencia nao pode ser nula.");
        }

        String[] parts = input.split(",");

        if (parts.length != EXPECTED_SIZE) {
            throw new IllegalArgumentException("Informe exatamente 16 valores decimais separados por virgula.");
        }

        byte[] result = new byte[EXPECTED_SIZE];

        for (int i = 0; i < parts.length; i++) {
            String value = parts[i].trim();

            if (value.isEmpty()) {
                throw new IllegalArgumentException("Valor decimal vazio na posicao " + (i + 1) + ".");
            }

            int parsed;

            try {
                parsed = Integer.parseInt(value);
            } catch (NumberFormatException exception) {
                throw new IllegalArgumentException("Valor decimal invalido na posicao " + (i + 1) + ": " + value);
            }

            if (parsed < 0 || parsed > 255) {
                throw new IllegalArgumentException("Valor fora do intervalo 0-255 na posicao " + (i + 1) + ".");
            }

            result[i] = (byte) parsed;
        }

        return result;
    }
}
