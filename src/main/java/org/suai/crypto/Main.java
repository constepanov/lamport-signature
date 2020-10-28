package org.suai.crypto;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import org.suai.crypto.lamport.LamportPublicKey;
import org.suai.crypto.lamport.LamportSignature;
import org.suai.crypto.util.SignatureAnalyzer;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import static org.suai.crypto.util.SignatureUtil.*;

public class Main {

    @Parameter(names={"--length", "-l"}, description = "Random message length in bytes")
    private int messageLength;
    @Parameter(names={"--mode", "-m"},
            description = "Mode allowed values: sign, verify, analysis",
            required = true)
    private String mode;
    @Parameter(names={"--help", "-h"}, help = true)
    private boolean help = false;

    public static void main(String... args) throws NoSuchAlgorithmException, IOException {
        Main main = new Main();
        JCommander jCommander = JCommander.newBuilder()
                .addObject(main)
                .build();
        jCommander.parse(args);
        if (main.help) {
            jCommander.usage();
            return;
        }
        main.run();
    }

    public void run() throws IOException, NoSuchAlgorithmException {
        final String baseDir = "src/main/resources/";
        Path messagePath = Path.of(baseDir, "message");
        Path signaturePath = Path.of(baseDir, "signature");
        Path publicKeyPath = Path.of(baseDir, "public-key");

        switch (mode) {
            case "sign": {
                byte[] message = generateRandomMessage(messageLength);
                int messageBitLength = new BigInteger(1, message).bitLength();
                LamportSignature lamport = new LamportSignature(messageBitLength);

                KeyPair keyPair = lamport.generateKeyPair();
                BigInteger[] signature = lamport.sign(message, keyPair.getPrivate());

                saveMessageAsBitString(message, messagePath);
                saveBigIntegerArray(signature, signaturePath);
                BigInteger[][] key = ((LamportPublicKey) keyPair.getPublic()).getKey();
                saveBigIntegerPairArray(key, publicKeyPath);
                break;
            }
            case "verify": {
                byte[] message = readBinaryMessage(messagePath);
                int messageBitLength = new BigInteger(1, message).bitLength();
                LamportSignature lamport = new LamportSignature(messageBitLength);

                BigInteger[] signature = readBigIntegerArray(signaturePath);
                BigInteger[][] key = readBigIntegerPairArray(publicKeyPath);

                PublicKey publicKey = new LamportPublicKey(key);
                boolean signatureStatus = lamport.verify(message, signature, publicKey);
                System.out.println("Signature status: " + signatureStatus);
                break;
            }
            case "analysis": {
                SignatureAnalyzer.plotSignatureSignAndVerifyTimeDependenceOnMessageSize();
                break;
            }
            default:
                throw new IllegalArgumentException("Unknown program mode");
        }
    }
}
