package com.zetes.projects.bosa.signandvalidation.model;

import com.zetes.projects.bosa.signingconfigurator.model.ClientSignatureParameters;
import eu.europa.esig.dss.ws.dto.RemoteDocument;

import java.util.List;

public class GetDataToSignMultipleDTO {

    private List<RemoteDocument> toSignDocuments;
    private String signingProfileId;
    private ClientSignatureParameters clientSignatureParameters;

    public GetDataToSignMultipleDTO() {
    }

    public GetDataToSignMultipleDTO(List<RemoteDocument> toSignDocuments, String signingProfileId, ClientSignatureParameters clientSignatureParameters) {
        this.toSignDocuments = toSignDocuments;
        this.signingProfileId = signingProfileId;
        this.clientSignatureParameters = clientSignatureParameters;
    }

    public List<RemoteDocument> getToSignDocuments() {
        return toSignDocuments;
    }

    public void setToSignDocuments(List<RemoteDocument> toSignDocuments) {
        this.toSignDocuments = toSignDocuments;
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
