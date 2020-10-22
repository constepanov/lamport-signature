package org.suai.crypto.lamport;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

public class LamportSignatureTest {

    @Test
    public void testSignatureVerified() throws NoSuchAlgorithmException {
        String message = "hello";
        LamportSignature lamport = new LamportSignature(message.length() * 8);
        KeyPair keyPair = lamport.generateKeyPair();
        BigInteger[] signature = lamport.sign(message.getBytes(), keyPair.getPrivate());
        boolean signatureStatus = lamport.verify(message.getBytes(), signature, keyPair.getPublic());
        Assertions.assertTrue(signatureStatus);
    }

    @Test
    public void testSignatureWrongIfMessageModified() throws NoSuchAlgorithmException {
        String message = "hello";
        LamportSignature lamport = new LamportSignature(message.length() * 8);
        KeyPair keyPair = lamport.generateKeyPair();
        BigInteger[] signature = lamport.sign(message.getBytes(), keyPair.getPrivate());
        message = "hellp";
        boolean signatureStatus = lamport.verify(message.getBytes(), signature, keyPair.getPublic());
        Assertions.assertFalse(signatureStatus);
    }
}
