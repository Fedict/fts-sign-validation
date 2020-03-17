package com.zetes.projects.bosa.signandvalidation.model;

import com.zetes.projects.bosa.signingconfigurator.model.ClientSignatureParameters;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import eu.europa.esig.dss.ws.dto.SignatureValueDTO;

public class SignDocumentDTO {

    private RemoteDocument toSignDocument;
    private String signingProfileId;
    private ClientSignatureParameters clientSignatureParameters;
    private SignatureValueDTO signatureValue;

    public SignDocumentDTO() {
    }

    public SignDocumentDTO(RemoteDocument toSignDocument, String signingProfileId, ClientSignatureParameters clientSignatureParameters, SignatureValueDTO signatureValue) {
        this.toSignDocument = toSignDocument;
        this.signingProfileId = signingProfileId;
        this.clientSignatureParameters = clientSignatureParameters;
        this.signatureValue = signatureValue;
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

    public SignatureValueDTO getSignatureValue() {
        return signatureValue;
    }

    public void setSignatureValue(SignatureValueDTO signatureValue) {
        this.signatureValue = signatureValue;
    }
}
