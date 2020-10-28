package org.suai.crypto.util;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class SignatureUtil {

    public static byte[] generateRandomMessage(int messageLength) {
        SecureRandom random = new SecureRandom();
        byte[] message = new byte[messageLength];
        random.nextBytes(message);
        return message;
    }

    public static void saveBigIntegerArray(BigInteger[] values, Path path) throws IOException {
        List<String> lines = Arrays.stream(values).map(BigInteger::toString).collect(Collectors.toList());
        Files.write(path, lines);
    }

    public static void saveBigIntegerPairArray(BigInteger[][] values, Path path) throws IOException {
        List<String> lines = IntStream.range(0, values[0].length)
                .mapToObj(i -> values[0][i].toString() + " " + values[1][i].toString())
                .collect(Collectors.toList());
        Files.write(path, lines);
    }

    public static BigInteger[] readBigIntegerArray(Path path) throws IOException {
        List<String> lines = Files.readAllLines(path);
        BigInteger[] values = new BigInteger[lines.size()];
        Arrays.setAll(values, i -> new BigInteger(lines.get(i)));
        return values;
    }

    public static BigInteger[][] readBigIntegerPairArray(Path path) throws IOException {
        List<String> lines = Files.readAllLines(path);
        BigInteger[][] values = new BigInteger[2][lines.size()];
        for (int i = 0; i < lines.size(); i++) {
            String[] line = lines.get(i).split(" ");
            values[0][i] = new BigInteger(line[0]);
            values[1][i] = new BigInteger(line[1]);
        }
        return values;
    }

    public static void saveMessageAsBitString(byte[] message, Path messagePath) throws IOException {
        String messageBitString = new BigInteger(message).toString(2);
        Files.writeString(messagePath, messageBitString);
    }

    public static byte[] readBinaryMessage(Path messagePath) throws IOException {
        String binaryString = Files.readString(messagePath);
        return new BigInteger(binaryString, 2).toByteArray();
    }
}
