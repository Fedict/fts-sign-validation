package com.zetes.projects.bosa.signandvalidation.model;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;

public class DataToSignDTO {

    private DigestAlgorithm digestAlgorithm;
    private byte[] digest;

    public DataToSignDTO() {
    }

    public DataToSignDTO(DigestAlgorithm digestAlgorithm, byte[] digest) {
        this.digestAlgorithm = digestAlgorithm;
        this.digest = digest;
    }

    public DigestAlgorithm getDigestAlgorithm() {
        return digestAlgorithm;
    }

    public void setDigestAlgorithm(DigestAlgorithm digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    public byte[] getDigest() {
        return digest;
    }

    public void setDigest(byte[] digest) {
        this.digest = digest;
    }

}
