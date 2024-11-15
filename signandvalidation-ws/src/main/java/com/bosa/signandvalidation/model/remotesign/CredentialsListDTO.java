package com.bosa.signandvalidation.model.remotesign;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class CredentialsListDTO {
    private List<String> credentialIDs;
    private List<CredentialInfo> credentialInfos;
    private String onlyValid;
}
