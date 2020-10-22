package org.suai.crypto.base;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public interface OneTimeSignature {
    KeyPair generateKeyPair();
    BigInteger[] sign(byte[] message, PrivateKey privateKey);
    boolean verify(byte[] message, BigInteger[] signature, PublicKey publicKey);
}
