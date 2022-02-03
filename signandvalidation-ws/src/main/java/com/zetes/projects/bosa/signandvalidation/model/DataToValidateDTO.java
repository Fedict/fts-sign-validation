package com.zetes.projects.bosa.signandvalidation.model;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Arrays;
import java.util.List;

@Data
@NoArgsConstructor
public class DataToValidateDTO {

    private RemoteDocument signedDocument;
    private List<RemoteDocument> originalDocuments;
    private RemoteDocument policy;
    private SignatureLevel level;

    public DataToValidateDTO(RemoteDocument signedDocument, RemoteDocument originalDocument, RemoteDocument policy) {
        this(signedDocument, originalDocument == null  ? null : Arrays.asList(originalDocument), policy);
    }

    public DataToValidateDTO(RemoteDocument signedDocument) {
        this(signedDocument, (List<RemoteDocument>) null, null);
    }

    public DataToValidateDTO(RemoteDocument signedDocument, List<RemoteDocument> originalDocuments) {
        this(signedDocument, originalDocuments, null);
    }

    public DataToValidateDTO(RemoteDocument signedDocument, List<RemoteDocument> originalDocuments, RemoteDocument policy) {
        this.originalDocuments = originalDocuments;
        this.signedDocument = signedDocument;
        this.policy = policy;
    }
}
