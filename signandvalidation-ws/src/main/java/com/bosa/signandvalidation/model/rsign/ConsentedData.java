package com.bosa.signandvalidation.model.rsign;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class ConsentedData {
    private String consentSessionId;
    private String hashAlgorithmOid;
    private AuthenticatedEidData eid;
    private AuthenticatedWalletData wallet;
}
