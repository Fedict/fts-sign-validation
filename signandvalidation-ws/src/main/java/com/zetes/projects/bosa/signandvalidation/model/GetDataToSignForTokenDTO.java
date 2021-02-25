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
public class GetDataToSignForTokenDTO {
    private String token;
    private String signingProfileId;
    private ClientSignatureParameters clientSignatureParameters;
    
    public GetDataToSignForTokenDTO() {
    }
    
    public GetDataToSignForTokenDTO(String token, String signingProfileId, ClientSignatureParameters clientSignatureParameters) {
        this.token = token;
        this.signingProfileId = signingProfileId;
        this.clientSignatureParameters = clientSignatureParameters;
    }
    
    public String getToken() {
        return token;
    }
    
    public void setToken(String token) {
        this.token = token;
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