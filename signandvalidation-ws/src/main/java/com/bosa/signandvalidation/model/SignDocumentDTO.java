package com.bosa.signandvalidation.model;

import com.bosa.signingconfigurator.model.ClientSignatureParameters;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import lombok.*;

@Setter @Getter @NoArgsConstructor @AllArgsConstructor
public class SignDocumentDTO {

    private RemoteDocument toSignDocument;
    private String signingProfileId;
    private ClientSignatureParameters clientSignatureParameters;
    private byte[] signatureValue;
    private RemoteDocument validatePolicy;
}
