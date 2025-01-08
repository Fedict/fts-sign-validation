package com.bosa.signandvalidation.model.remotesign;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class SignHashesDTO {
    private String credentialID;
    private String SAD;
    private List<byte []> hashes;
    private String hashAlgorithmOID;
    private String signAlgo;
    private String signAlgoParams;
    private SignOperation operationMode;
    private String validity_period;
    private String response_uri;
    private String clientData;
}
