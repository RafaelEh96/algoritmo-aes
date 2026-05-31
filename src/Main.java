import aes.Aes128;
import aes.ByteSequenceParser;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Locale;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {
        try {
            if (args.length > 0) {
                processArguments(args);
            } else {
                processInteractive();
            }
        } catch (Exception exception) {
            System.err.println("Erro: " + exception.getMessage());
            System.exit(1);
        }
    }

    private static void processArguments(String[] args) throws IOException {
        if (args.length != 5 && args.length != 6) {
            printUsage();
            throw new IllegalArgumentException("Quantidade de argumentos invalida.");
        }

        boolean encrypt = parseOperation(args[0]);
        String mode = normalizeMode(args[1]);
        Path inputPath = Paths.get(args[2]);
        Path outputPath = Paths.get(args[3]);
        byte[] key = ByteSequenceParser.parse16Bytes(args[4]);
        byte[] iv = null;

        if ("cbc".equals(mode)) {
            if (args.length != 6) {
                throw new IllegalArgumentException("O modo CBC exige um IV com 16 valores decimais.");
            }

            iv = ByteSequenceParser.parse16Bytes(args[5]);
        } else if (args.length == 6) {
            throw new IllegalArgumentException("O modo ECB nao utiliza IV.");
        }

        processFile(encrypt, mode, inputPath, outputPath, key, iv);
    }

    private static void processInteractive() throws IOException {
        try (Scanner scanner = new Scanner(System.in)) {
            System.out.println("AES-128");

            System.out.print("Operacao (cifrar/decifrar): ");
            boolean encrypt = parseOperation(scanner.nextLine());

            System.out.print("Modo (ECB/CBC): ");
            String mode = normalizeMode(scanner.nextLine());

            System.out.print("Arquivo de entrada: ");
            Path inputPath = Paths.get(scanner.nextLine().trim());

            System.out.print("Arquivo de saida: ");
            Path outputPath = Paths.get(scanner.nextLine().trim());

            System.out.print("Chave (16 decimais separados por virgula): ");
            byte[] key = ByteSequenceParser.parse16Bytes(scanner.nextLine());

            byte[] iv = null;

            if ("cbc".equals(mode)) {
                System.out.print("IV (16 decimais separados por virgula): ");
                iv = ByteSequenceParser.parse16Bytes(scanner.nextLine());
            }

            processFile(encrypt, mode, inputPath, outputPath, key, iv);
        }
    }

    private static void processFile(
            boolean encrypt,
            String mode,
            Path inputPath,
            Path outputPath,
            byte[] key,
            byte[] iv
    ) throws IOException {
        byte[] input = Files.readAllBytes(inputPath);
        byte[] output;

        if ("ecb".equals(mode)) {
            output = encrypt ? Aes128.cifrarEcb(input, key) : Aes128.decifrarEcb(input, key);
        } else {
            output = encrypt ? Aes128.cifrarCbc(input, key, iv) : Aes128.decifrarCbc(input, key, iv);
        }

        Files.write(outputPath, output);

        System.out.println("Arquivo gerado: " + outputPath.toAbsolutePath());
        System.out.println("Bytes lidos: " + input.length);
        System.out.println("Bytes escritos: " + output.length);
    }

    private static boolean parseOperation(String input) {
        String normalized = input.trim().toLowerCase(Locale.ROOT);

        if ("1".equals(normalized)
                || "cifrar".equals(normalized)
                || "criptografar".equals(normalized)
                || "encrypt".equals(normalized)) {
            return true;
        }

        if ("2".equals(normalized)
                || "decifrar".equals(normalized)
                || "descriptografar".equals(normalized)
                || "decrypt".equals(normalized)) {
            return false;
        }

        throw new IllegalArgumentException("Operacao invalida. Use cifrar ou decifrar.");
    }

    private static String normalizeMode(String input) {
        String normalized = input.trim().toLowerCase(Locale.ROOT);

        if ("1".equals(normalized) || "ecb".equals(normalized)) {
            return "ecb";
        }

        if ("2".equals(normalized) || "cbc".equals(normalized)) {
            return "cbc";
        }

        throw new IllegalArgumentException("Modo invalido. Use ECB ou CBC.");
    }

    private static void printUsage() {
        System.out.println("Uso:");
        System.out.println("  java Main cifrar|decifrar ecb entrada saida chave");
        System.out.println("  java Main cifrar|decifrar cbc entrada saida chave iv");
        System.out.println("Chave e IV: 16 valores decimais de 0 a 255 separados por virgula.");
    }
}
