package com.bosa.signandvalidation.model;

import com.bosa.signingconfigurator.model.ClientSignatureParameters;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class GetDataToSignForTokenDTO {
    private String token;
    private int fileIdToSign;
    private ClientSignatureParameters clientSignatureParameters;
}
