package com.bosa.signandvalidation.model;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;

public class CertificateIndicationsDTO {

    private String commonName;

    private Indication indication;

    private SubIndication subIndication;

    private boolean keyUsageCheckOk;

    public CertificateIndicationsDTO() {
    }

    public CertificateIndicationsDTO(String commonName, Indication indication, boolean keyUsageCheckOk) {
        this.commonName = commonName;
        this.indication = indication;
        this.keyUsageCheckOk = keyUsageCheckOk;
    }

    public CertificateIndicationsDTO(String commonName, Indication indication, SubIndication subIndication, boolean keyUsageCheckOk) {
        this.commonName = commonName;
        this.indication = indication;
        this.subIndication = subIndication;
        this.keyUsageCheckOk = keyUsageCheckOk;
    }

    public String getCommonName() {
        return commonName;
    }

    public void setCommonName(String commonName) {
        this.commonName = commonName;
    }

    public Indication getIndication() {
        return indication;
    }

    public void setIndication(Indication indication) {
        this.indication = indication;
    }

    public SubIndication getSubIndication() {
        return subIndication;
    }

    public void setSubIndication(SubIndication subIndication) {
        this.subIndication = subIndication;
    }

    public boolean isKeyUsageCheckOk() {
        return keyUsageCheckOk;
    }

    public void setKeyUsageCheckOk(boolean keyUsageCheckOk) {
        this.keyUsageCheckOk = keyUsageCheckOk;
    }
}
