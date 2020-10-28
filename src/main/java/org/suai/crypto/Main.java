package org.suai.crypto;

import org.suai.crypto.lamport.LamportPublicKey;
import org.suai.crypto.lamport.LamportSignature;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        boolean signMode = false;
        final int messageLength = 4;
        final String baseDir = "src/main/resources/";
        Path messagePath = Path.of(baseDir, "message");
        Path signaturePath = Path.of(baseDir, "signature");
        Path publicKeyPath = Path.of(baseDir, "public-key");
        LamportSignature lamport = new LamportSignature(messageLength * 8);
        if (signMode) {
            byte[] message = generateRandomMessage(messageLength);
            KeyPair keyPair = lamport.generateKeyPair();
            BigInteger[] signature = lamport.sign(message, keyPair.getPrivate());

            saveMessageAsBitString(message, messagePath);
            saveBigIntegerArray(signature, signaturePath);
            BigInteger[][] key = ((LamportPublicKey) keyPair.getPublic()).getKey();
            saveBigIntegerPairArray(key, publicKeyPath);
        } else {
            byte[] message = readBinaryMessage(messagePath);
            BigInteger[] signature = readBigIntegerArray(signaturePath);
            BigInteger[][] key = readBigIntegerPairArray(publicKeyPath);
            PublicKey publicKey = new LamportPublicKey(key);
            boolean signatureStatus = lamport.verify(message, signature, publicKey);
            System.out.println("Signature status: " + signatureStatus);
        }
        //SignatureAnalyzer.plotSignatureSignAndVerifyTimeDependenceOnMessageSize();
    }

    private static byte[] generateRandomMessage(int messageLength) {
        SecureRandom random = new SecureRandom();
        byte[] message = new byte[messageLength];
        random.nextBytes(message);
        return message;
    }

    private static void saveBigIntegerArray(BigInteger[] values, Path path) throws IOException {
        List<String> lines = Arrays.stream(values).map(BigInteger::toString).collect(Collectors.toList());
        Files.write(path, lines);
    }

    private static void saveBigIntegerPairArray(BigInteger[][] values, Path path) throws IOException {
        List<String> lines = IntStream.range(0, values[0].length)
                .mapToObj(i -> values[0][i].toString() + " " + values[1][i].toString())
                .collect(Collectors.toList());
        Files.write(path, lines);
    }

    private static BigInteger[] readBigIntegerArray(Path path) throws IOException {
        List<String> lines = Files.readAllLines(path);
        BigInteger[] values = new BigInteger[lines.size()];
        Arrays.setAll(values, i -> new BigInteger(lines.get(i)));
        return values;
    }

    private static BigInteger[][] readBigIntegerPairArray(Path path) throws IOException {
        List<String> lines = Files.readAllLines(path);
        BigInteger[][] values = new BigInteger[2][lines.size()];
        for (int i = 0; i < lines.size(); i++) {
            String[] line = lines.get(i).split(" ");
            values[0][i] = new BigInteger(line[0]);
            values[1][i] = new BigInteger(line[1]);
        }
        return values;
    }

    private static void saveMessageAsBitString(byte[] message, Path messagePath) throws IOException {
        String messageBitString = new BigInteger(message).toString(2);
        Files.writeString(messagePath, messageBitString);
    }

    private static byte[] readBinaryMessage(Path messagePath) throws IOException {
        String binaryString = Files.readString(messagePath);
        return new BigInteger(binaryString, 2).toByteArray();
    }
}
