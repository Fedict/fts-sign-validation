package com.zetes.projects.bosa.signandvalidation.model;

import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;

import java.util.Date;
import java.util.List;

public class CertificateToValidateDTO {

    private RemoteCertificate certificate;

    private List<RemoteCertificate> certificateChain;

    private Date validationTime;

    private KeyUsageBit expectedKeyUsage;

    public CertificateToValidateDTO() {
    }

    public CertificateToValidateDTO(RemoteCertificate certificate, List<RemoteCertificate> certificateChain, Date validationTime, KeyUsageBit expectedKeyUsage) {
        this.certificate = certificate;
        this.certificateChain = certificateChain;
        this.validationTime = validationTime;
        this.expectedKeyUsage = expectedKeyUsage;
    }


    public RemoteCertificate getCertificate() {
        return certificate;
    }

    public void setCertificate(RemoteCertificate certificate) {
        this.certificate = certificate;
    }

    public List<RemoteCertificate> getCertificateChain() {
        return certificateChain;
    }

    public void setCertificateChain(List<RemoteCertificate> certificateChain) {
        this.certificateChain = certificateChain;
    }

    public Date getValidationTime() {
        return validationTime;
    }

    public void setValidationTime(Date validationTime) {
        this.validationTime = validationTime;
    }

    public KeyUsageBit getExpectedKeyUsage() {
        return expectedKeyUsage;
    }

    public void setExpectedKeyUsage(KeyUsageBit expectedKeyUsage) {
        this.expectedKeyUsage = expectedKeyUsage;
    }

}
