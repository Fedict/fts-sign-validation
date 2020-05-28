package com.zetes.projects.bosa.signandvalidation.model;

import com.zetes.projects.bosa.signingconfigurator.model.ClientSignatureParameters;
import eu.europa.esig.dss.ws.dto.RemoteDocument;

public class GetDataToSignDTO {

    private RemoteDocument toSignDocument;
    private String signingProfileId;
    private ClientSignatureParameters clientSignatureParameters;

    public GetDataToSignDTO() {
    }

    public GetDataToSignDTO(RemoteDocument toSignDocument, String signingProfileId, ClientSignatureParameters clientSignatureParameters) {
        this.toSignDocument = toSignDocument;
        this.signingProfileId = signingProfileId;
        this.clientSignatureParameters = clientSignatureParameters;
    }

    public RemoteDocument getToSignDocument() {
        return toSignDocument;
    }

    public void setToSignDocument(RemoteDocument toSignDocument) {
        this.toSignDocument = toSignDocument;
    }

    public String getSigningProfileId() {
        return signingProfileId;
    }

    public void setSigningProfileId(String signingProfileId) {
        this.signingProfileId = signingProfileId;
    }

    public ClientSignatureParameters getClientSignatureParameters() {
        return clientSignatureParameters;
    }

    public void setClientSignatureParameters(ClientSignatureParameters clientSignatureParameters) {
        this.clientSignatureParameters = clientSignatureParameters;
    }
}
