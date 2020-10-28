package org.suai.crypto;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import org.suai.crypto.lamport.LamportPublicKey;
import org.suai.crypto.lamport.LamportSignature;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import static org.suai.crypto.util.SignatureUtil.*;

public class Main {

    @Parameter(names={"--length", "-l"}, description = "Message length in bytes")
    int messageLength;
    @Parameter(names = "-sign", description = "Sign mode - true, Verify mode - false")
    boolean signMode = false;

    public static void main(String... args) throws NoSuchAlgorithmException, IOException {
        Main main = new Main();
        JCommander.newBuilder()
                .addObject(main)
                .build()
                .parse(args);
        main.run();
        //SignatureAnalyzer.plotSignatureSignAndVerifyTimeDependenceOnMessageSize();
    }

    public void run() throws IOException, NoSuchAlgorithmException {
        final String baseDir = "src/main/resources/";
        Path messagePath = Path.of(baseDir, "message");
        Path signaturePath = Path.of(baseDir, "signature");
        Path publicKeyPath = Path.of(baseDir, "public-key");
        if (signMode) {
            LamportSignature lamport = new LamportSignature(messageLength * 8);
            byte[] message = generateRandomMessage(messageLength);
            KeyPair keyPair = lamport.generateKeyPair();
            BigInteger[] signature = lamport.sign(message, keyPair.getPrivate());

            saveMessageAsBitString(message, messagePath);
            saveBigIntegerArray(signature, signaturePath);
            BigInteger[][] key = ((LamportPublicKey) keyPair.getPublic()).getKey();
            saveBigIntegerPairArray(key, publicKeyPath);
        } else {
            byte[] message = readBinaryMessage(messagePath);
            LamportSignature lamport = new LamportSignature(message.length * 8);
            BigInteger[] signature = readBigIntegerArray(signaturePath);
            BigInteger[][] key = readBigIntegerPairArray(publicKeyPath);
            PublicKey publicKey = new LamportPublicKey(key);
            boolean signatureStatus = lamport.verify(message, signature, publicKey);
            System.out.println("Signature status: " + signatureStatus);
        }
    }
}
