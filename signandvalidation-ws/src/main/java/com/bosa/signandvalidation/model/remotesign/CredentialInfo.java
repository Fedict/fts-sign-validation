package com.bosa.signandvalidation.model.remotesign;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class CredentialInfo {
    private String credentialID;
    private String description;
    private String signatureQualifier;
    private RemoteKeyInfo key;
    private RemoteCertInfo cert;
    private RemoteAuthInfo auth;
    private String SCAL;
    private Integer multisign;
    private String lang;
}
