package org.suai.crypto.lamport;

import org.suai.crypto.base.OneTimeSignature;

import java.math.BigInteger;
import java.security.*;

public class LamportSignature implements OneTimeSignature {

    private static final int RANDOM_NUMBER_BIT_LENGTH = 256;
    private static final String HASH_ALGORITHM = "SHA-256";

    private final SecureRandom random;
    private final MessageDigest digest;
    private final int numberOfPairs;

    public LamportSignature(int messageBitLength) throws NoSuchAlgorithmException {
        this.numberOfPairs = messageBitLength;
        this.random = new SecureRandom();
        this.digest = MessageDigest.getInstance(HASH_ALGORITHM);
    }

    public KeyPair generateKeyPair() {
        BigInteger[][] privateKey = new BigInteger[2][numberOfPairs];
        BigInteger[][] publicKey = new BigInteger[2][numberOfPairs];

        for (int i = 0; i < numberOfPairs; i++) {
            privateKey[0][i] = new BigInteger(RANDOM_NUMBER_BIT_LENGTH, random);
            privateKey[1][i] = new BigInteger(RANDOM_NUMBER_BIT_LENGTH, random);

            publicKey[0][i] = new BigInteger(digest.digest(privateKey[0][i].toByteArray()));
            publicKey[1][i] = new BigInteger(digest.digest(privateKey[1][i].toByteArray()));
        }

        return new KeyPair(new LamportPublicKey(publicKey), new LamportPrivateKey(privateKey));
    }

    public BigInteger[] sign(byte[] message, PrivateKey privateKey) {
        BigInteger[] signature = new BigInteger[numberOfPairs];
        BigInteger messageIntRepresentation = new BigInteger(message);
        BigInteger[][] key = ((LamportPrivateKey) privateKey).getKey();
        for (int i = 0; i < numberOfPairs; i++) {
            int bit = messageIntRepresentation.shiftRight(i).and(BigInteger.ONE).intValue();
            signature[i] = key[bit][i];
        }
        return signature;
    }

    public boolean verify(byte[] message, BigInteger[] signature, PublicKey publicKey) {
        BigInteger messageIntRepresentation = new BigInteger(message);
        BigInteger[][] key = ((LamportPublicKey) publicKey).getKey();
        for (int i = 0; i < numberOfPairs; i++) {
            int bit = messageIntRepresentation.shiftRight(i).and(BigInteger.ONE).intValue();
            BigInteger checkHash = new BigInteger(digest.digest(signature[i].toByteArray()));
            if (!checkHash.equals(key[bit][i])) {
                return false;
            }
        }
        return true;
    }
}
