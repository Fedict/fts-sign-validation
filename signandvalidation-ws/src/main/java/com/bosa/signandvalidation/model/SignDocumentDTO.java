package com.bosa.signandvalidation.model;

import com.bosa.signingconfigurator.model.ClientSignatureParameters;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SignDocumentDTO {

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "A file to be signed")
    private RemoteDocument toSignDocument;
    @Schema(example = "XADES_LTA", requiredMode = Schema.RequiredMode.REQUIRED, description = "The signing profile to use")
    private String signingProfileId;
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Signature parameters")
    private ClientSignatureParameters clientSignatureParameters;
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "The signed digest (from getDataToSign)")
    private byte[] signatureValue;
    @Schema(description = "A file that contains a 'policy.xml' validation policy used. Mainly used to accommodate non-prod certificates used in test cases")
    private RemoteDocument validatePolicy;
    @Schema(description = "A logging identifier for the current user session")
    private String token;
}
