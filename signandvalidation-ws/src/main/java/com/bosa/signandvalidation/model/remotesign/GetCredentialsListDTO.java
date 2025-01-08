package com.bosa.signandvalidation.model.remotesign;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class GetCredentialsListDTO {
    private String userID;
    private boolean credentialInfo;
    private boolean certificates;
    private boolean certInfo;
    private boolean authInfo;
    private String onlyValid;
    private String lang;
    private String clientData;
}
