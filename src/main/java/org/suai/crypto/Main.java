package org.suai.crypto;

import org.suai.crypto.lamport.LamportSignature;
import org.suai.crypto.util.SignatureAnalyzer;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        String message = "hello";

        LamportSignature lamport = new LamportSignature(message.length() * 8);
        KeyPair keyPair = lamport.generateKeyPair();
        BigInteger[] signature = lamport.sign(message.getBytes(), keyPair.getPrivate());
        boolean signatureStatus = lamport.verify(message.getBytes(), signature, keyPair.getPublic());
        System.out.println(signatureStatus);
        SignatureAnalyzer.plotSignatureSizeDependenceOnMessageSize();
    }
}
