package org.suai.crypto;

import org.suai.crypto.lamport.LamportSignature;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        final String baseDir = "src/main/resources/";
        final int messageLength = 4;
        Path messagePath = Path.of(baseDir, "message");
        Path signaturePath = Path.of(baseDir, "signature");

        byte[] message = generateRandomMessage(messageLength);
        saveMessageAsBitString(message, messagePath);

        LamportSignature lamport = new LamportSignature(message.length * 8);
        KeyPair keyPair = lamport.generateKeyPair();
        BigInteger[] signature = lamport.sign(message, keyPair.getPrivate());
        boolean signatureStatus = lamport.verify(message, signature, keyPair.getPublic());
        Files.writeString(signaturePath, Arrays.toString(signature));
        System.out.println(signatureStatus);
        //SignatureAnalyzer.plotSignatureSignAndVerifyTimeDependenceOnMessageSize();
    }

    private static byte[] generateRandomMessage(int messageLength) {
        SecureRandom random = new SecureRandom();
        byte[] message = new byte[messageLength];
        random.nextBytes(message);
        return message;
    }

    private static void saveMessageAsBitString(byte[] message, Path messagePath) throws IOException {
        String messageBitString = new BigInteger(message).toString(2);
        Files.writeString(messagePath, messageBitString);
    }
}
