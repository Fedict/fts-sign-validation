/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.bosa.signandvalidation.model;

import com.bosa.signingconfigurator.model.ClientSignatureParameters;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 *
 * @author wouter
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class SignDocumentForTokenDTO {
    private String token;
    private int fileIdToSign;
    private String psfN;
    private String psfC;
    private ClientSignatureParameters clientSignatureParameters;
    private byte[] signatureValue;
}
