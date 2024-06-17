package com.bosa.signandvalidation.model;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

import java.util.Date;

@Data
public class NormalizedSignatureInfo {
    // Validation info
    @Schema(description = "The signature is qualified (See EIDAS qualification)")
    private boolean     qualified;
    @Schema(description = "The signature is cryptographically valid")
    private boolean     valid;
    @Schema(description = "The signature does not contain the signing certificate")
    private boolean     missingSigningCert;         // Use case : PDF signed with Adobe in 'PKCS7' format
    @Schema(description = "If the signature is not valid, it contains the error type")
    private String      subIndication;

    // Signature info
    @Schema(description = "The time, extracted from the signature, of the signature")
    private Date        claimedSigningTime;
    @Schema(description = "The time, confirmed by reputable sources (TS, OCSP, CRLs, of the signature")
    private Date        bestSigningTime;
    @Schema(description = "The 'common name' found in the signing certificate")
    private String      signerCommonName;
    @Schema(description = "A mix of Signature format (PADES/CADES/XADES/JADES/...), signature types (B/LT/LTA/...)")
    private SignatureLevel  signatureFormat;
}
