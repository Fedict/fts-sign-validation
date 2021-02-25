/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.zetes.projects.bosa.signandvalidation.model;

import com.zetes.projects.bosa.signingconfigurator.model.ClientSignatureParameters;

/**
 *
 * @author wouter
 */
public class SignDocumentForTokenDTO {
    private ClientSignatureParameters clientSignatureParameters;
    private String token;
    private byte[] signatureValue;
    
    public SignDocumentForTokenDTO() {
    }
    public SignDocumentForTokenDTO(String token, ClientSignatureParameters clientSignatureParameters, byte[] signatureValue) {
        this.clientSignatureParameters = clientSignatureParameters;
        this.token = token;
        this.signatureValue = signatureValue;
    }
    public String getToken() {
        return token;
    }
    public byte[] getSignatureValue() {
        return signatureValue;
    }
    public ClientSignatureParameters getClientSignatureParameters() {
        return clientSignatureParameters;
    }
}
