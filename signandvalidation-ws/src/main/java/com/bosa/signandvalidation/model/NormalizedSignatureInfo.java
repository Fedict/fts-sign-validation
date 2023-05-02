package com.bosa.signandvalidation.model;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import lombok.Data;

import java.util.Date;

@Data
public class NormalizedSignatureInfo {
    // Validation info
    private boolean     isQualified;
    private boolean     isValid;
    private boolean     missingSigningCert;         // Use case : PDF signed with Adobe in 'PKCS7' format
    private String      subIndication;

    // Signature info
    private Date        claimedSigningTime;
    private Date        bestSigningTime;
    private String      signerCommonName;
    private String      signatureFormat;
}
