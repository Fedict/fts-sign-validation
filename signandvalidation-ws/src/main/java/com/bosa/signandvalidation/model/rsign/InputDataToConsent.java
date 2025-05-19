package com.bosa.signandvalidation.model.rsign;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

@Getter
@AllArgsConstructor
public class InputDataToConsent {
    private String clientData;
    private String authSessionId;
    private String hashAlgorithmOID;
    private List<DocumentDigest> hashesToSign;
}
