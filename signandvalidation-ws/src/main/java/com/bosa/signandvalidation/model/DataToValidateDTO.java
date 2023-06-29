package com.bosa.signandvalidation.model;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Arrays;
import java.util.List;

@Data
@NoArgsConstructor
public class DataToValidateDTO {

    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = "The base 64 encoded document to validate.<BR>" +
            "It contains 3 fields : <UL>"+
            "<LI>bytes : (mandatory) = base 64 encoded data to validate</LI>" +
            "<LI>'digestAlgorithm' : (optional) = DO NOT USE</LI>" +
            "<LI>'name' : (optional) = DO NOT USE</LI>" +
            "</UL>")
    private RemoteDocument signedDocument;

    @Schema(description = "For detached signatures, the list of documents that are covered by the signature(s)")
    private List<RemoteDocument> originalDocuments;

    @Schema(description = "The base 64 encoded 'policy.xml' file to use for the validation.<BR>Mainly used to allow tests to validate test certificates")
    private RemoteDocument policy;

    @Schema(example = "XAdES_BASELINE_B", description = "Expected signature level of every signature in the file." +
            "<BR>If a signature has a different level validation fails")
    private SignatureLevel level;

    public DataToValidateDTO(RemoteDocument signedDocument) {
        this.signedDocument = signedDocument;
    }

    public DataToValidateDTO(RemoteDocument signedDocument, RemoteDocument originalDocument) {
        this(signedDocument, originalDocument, null);
    }

    public DataToValidateDTO(RemoteDocument signedDocument, RemoteDocument originalDocument, RemoteDocument policy) {
        this.policy = policy;
        this.signedDocument = signedDocument;
        if (originalDocument != null) this.originalDocuments = Arrays.asList(originalDocument);
    }
}
