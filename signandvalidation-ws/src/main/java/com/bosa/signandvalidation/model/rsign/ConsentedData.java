package com.bosa.signandvalidation.model.rsign;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ConsentedData {
    private String consentSessionId;
    private AuthenticatedEidData eid;
    private AuthenticatedWalletData wallet;
}
