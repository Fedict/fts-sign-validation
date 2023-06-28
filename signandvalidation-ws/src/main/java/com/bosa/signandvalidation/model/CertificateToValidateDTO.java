package com.bosa.signandvalidation.model;

import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import io.swagger.v3.oas.annotations.media.Schema;

import java.util.Date;
import java.util.List;

public class CertificateToValidateDTO {

    @Schema(name = "certificate", requiredMode = Schema.RequiredMode.REQUIRED, description = "The certificate to validate." +
            "It contains 1 field : encodedCertificate = base 64 encoded certificate to validate")
    private RemoteCertificate certificate;

    @Schema(name = "certificateChain", description = "The list of parent certificates of the cert. to validate.<BR>" +
            "If not provided the 'Authority Information Access' will be used to retrieve the certificates")
    private List<RemoteCertificate> certificateChain;

    @Schema(name = "validationTime", description = "Not used")
    private Date validationTime;

    @Schema(name = "expectedKeyUsage", requiredMode = Schema.RequiredMode.REQUIRED, description = "The type of signatures that this certificate must be able to do ")
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
        if(validationTime == null) {
            validationTime = new Date();
        }
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
