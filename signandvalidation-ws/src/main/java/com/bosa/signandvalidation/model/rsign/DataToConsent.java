package com.bosa.signandvalidation.model.rsign;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class DataToConsent {
    private String consentSessionId;
    private EIDAuthenticatorInfo eid;
    private WalletAuthenticatorInfo wallet;

    public DataToConsent(String consentSessionId, WalletAuthenticatorInfo wallet) {
        this.consentSessionId = consentSessionId;
        this.wallet = wallet;
    }

    public DataToConsent(String consentSessionId, EIDAuthenticatorInfo eid) {
        this.consentSessionId = consentSessionId;
        this.eid = eid;
    }
}
