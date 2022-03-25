package com.bosa.signandvalidation.model;

import com.bosa.signingconfigurator.model.ClientSignatureParameters;
import eu.europa.esig.dss.ws.dto.RemoteDocument;

import java.util.List;

public class SignDocumentMultipleDTO {

    private List<RemoteDocument> toSignDocuments;
    private String signingProfileId;
    private ClientSignatureParameters clientSignatureParameters;
    private byte[] signatureValue;

    public SignDocumentMultipleDTO() {
    }

    public SignDocumentMultipleDTO(List<RemoteDocument> toSignDocuments, String signingProfileId, ClientSignatureParameters clientSignatureParameters, byte[] signatureValue) {
        this.toSignDocuments = toSignDocuments;
        this.signingProfileId = signingProfileId;
        this.clientSignatureParameters = clientSignatureParameters;
        this.signatureValue = signatureValue;
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

    public byte[] getSignatureValue() {
        return signatureValue;
    }

    public void setSignatureValue(byte[] signatureValue) {
        this.signatureValue = signatureValue;
    }
}
