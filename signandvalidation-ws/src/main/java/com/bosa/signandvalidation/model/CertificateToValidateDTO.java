package com.bosa.signandvalidation.model;

import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CertificateToValidateDTO {

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "The certificate to validate." +
            "It contains 1 field : encodedCertificate = base 64 encoded certificate to validate")
    private RemoteCertificate certificate;

    @Schema(description = "The list of parent certificates of the cert. to validate.<BR>" +
            "If not provided the 'Authority Information Access' will be used to retrieve the certificates")
    private List<RemoteCertificate> certificateChain;

    @Schema(description = "Not used")
    private Date validationTime;

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "The type of signatures that this certificate must be able to do ")
    private KeyUsageBit expectedKeyUsage;

    @Schema(description = "A logging identifier for the current user session")
    private String token;

    public Date getValidationTime() {
        if(validationTime == null) {
            validationTime = new Date();
        }
        return validationTime;
    }
}
