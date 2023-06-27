package com.bosa.signandvalidation.model;

import com.bosa.signingconfigurator.model.ClientSignatureParameters;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
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

    private List<RemoteDocument> toSignDocuments;
    private String signingProfileId;
    private ClientSignatureParameters clientSignatureParameters;
    private byte[] signatureValue;
    private RemoteDocument validatePolicy;
}
