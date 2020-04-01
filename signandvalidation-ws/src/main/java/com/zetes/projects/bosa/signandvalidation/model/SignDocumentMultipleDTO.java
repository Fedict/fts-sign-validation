package com.zetes.projects.bosa.signandvalidation.model;

import com.zetes.projects.bosa.signingconfigurator.model.ClientSignatureParameters;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;

import java.util.List;

public class SignDocumentMultipleDTO {

    private List<RemoteDocument> toSignDocuments;
    private String signingProfileId;
    private ClientSignatureParameters clientSignatureParameters;
    private SignatureValueDTO signatureValue;

    public SignDocumentMultipleDTO() {
    }

    public SignDocumentMultipleDTO(List<RemoteDocument> toSignDocuments, String signingProfileId, ClientSignatureParameters clientSignatureParameters, SignatureValueDTO signatureValue) {
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

    public SignatureValueDTO getSignatureValue() {
        return signatureValue;
    }

    public void setSignatureValue(SignatureValueDTO signatureValue) {
        this.signatureValue = signatureValue;
    }
}
