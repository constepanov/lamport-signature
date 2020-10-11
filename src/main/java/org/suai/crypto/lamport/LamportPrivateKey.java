package org.suai.crypto.lamport;

import java.math.BigInteger;
import java.security.PrivateKey;

public class LamportPrivateKey implements PrivateKey {

    private BigInteger[][] key;

    public LamportPrivateKey(BigInteger[][] key) {
        this.key = key;
    }

    public BigInteger[][] getKey() {
        return key;
    }

    @Override
    public String getAlgorithm() {
        return "Lamport";
    }

    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public byte[] getEncoded() {
        return null;
    }
}
