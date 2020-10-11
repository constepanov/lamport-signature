package org.suai.crypto.lamport;

import java.math.BigInteger;
import java.security.*;

public class LamportSignature {

    private final int numberOfPairs = 256;
    private final int randomNumberBitLength = 256;
    private final String hashAlgorithm = "SHA-256";

    private final SecureRandom random;
    private final MessageDigest digest;

    public LamportSignature() throws NoSuchAlgorithmException {
        this.random = new SecureRandom();
        this.digest = MessageDigest.getInstance(hashAlgorithm);
    }

    public KeyPair generateKeyPair() {
        BigInteger[][] privateKey = new BigInteger[2][numberOfPairs];
        BigInteger[][] publicKey = new BigInteger[2][numberOfPairs];

        for (int i = 0; i < numberOfPairs; i++) {
            privateKey[0][i] = new BigInteger(randomNumberBitLength, random);
            privateKey[1][i] = new BigInteger(randomNumberBitLength, random);

            publicKey[0][i] = new BigInteger(digest.digest(privateKey[0][i].toByteArray()));
            publicKey[1][i] = new BigInteger(digest.digest(privateKey[1][i].toByteArray()));
        }

        return new KeyPair(new LamportPublicKey(publicKey), new LamportPrivateKey(privateKey));
    }

    public BigInteger[] sign(byte[] message, PrivateKey privateKey) {
        BigInteger[] signature = new BigInteger[numberOfPairs];
        BigInteger hash = new BigInteger(digest.digest(message));
        BigInteger[][] key = ((LamportPrivateKey) privateKey).getKey();
        for (int i = 0; i < numberOfPairs; i++) {
            int bit = hash.shiftRight(i).and(BigInteger.ONE).intValue();
            signature[i] = key[bit][i];
        }
        return signature;
    }

    public boolean verify(byte[] message, BigInteger[] signature, PublicKey publicKey) {
        BigInteger hash = new BigInteger(digest.digest(message));
        BigInteger[][] key = ((LamportPublicKey) publicKey).getKey();
        for (int i = 0; i < numberOfPairs; i++) {
            int bit = hash.shiftRight(i).and(BigInteger.ONE).intValue();
            BigInteger checkHash = new BigInteger(digest.digest(signature[i].toByteArray()));
            if (!checkHash.equals(key[bit][i])) {
                return false;
            }
        }
        return true;
    }
}
