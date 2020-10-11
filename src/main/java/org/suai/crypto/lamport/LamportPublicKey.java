package org.suai.crypto.lamport;

import java.math.BigInteger;
import java.security.PublicKey;

public class LamportPublicKey implements PublicKey {

    private BigInteger[][] key;

    public LamportPublicKey(BigInteger[][] key) {
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
