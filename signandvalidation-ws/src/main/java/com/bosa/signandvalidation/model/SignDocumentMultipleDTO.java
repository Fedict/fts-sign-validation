package com.bosa.signandvalidation.model;

import com.bosa.signingconfigurator.model.ClientSignatureParameters;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class SignDocumentMultipleDTO {

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "A list of files to be signed")
    private List<RemoteDocument> toSignDocuments;
    @Schema(example = "XADES_LTA", requiredMode = Schema.RequiredMode.REQUIRED, description = "The signing profile to use")
    private String signingProfileId;
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "Signature parameters")
    private ClientSignatureParameters clientSignatureParameters;
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "The signed digest (from getDataToSign)")
    private byte[] signatureValue;
    @Schema(description = "A file that contains a 'policy.xml' validation policy used. Mainly used to accommodate non-prod certificates used in test cases")
    private RemoteDocument validatePolicy;
}
