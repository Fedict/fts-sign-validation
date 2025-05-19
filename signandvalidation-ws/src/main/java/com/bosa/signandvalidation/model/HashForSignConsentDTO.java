/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.bosa.signandvalidation.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class HashForSignConsentDTO {
    private String authSessionId;
    private String token;
    private List<InputToBeSigned> inputsToSign;
    private String signLanguage;
    private String clientData;
}
