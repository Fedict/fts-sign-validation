package com.bosa.signandvalidation.model;

import com.bosa.signandvalidation.model.rsign.EIDAuthenticatorInfo;
import com.bosa.signandvalidation.model.rsign.WalletAuthenticatorInfo;
import com.fasterxml.jackson.annotation.JsonFormat;
import eu.europa.esig.dss.ws.dto.RemoteCertificate;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.Date;
import java.util.List;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class HashForSignatureConsentDTO {
    private String consentSessionId;
    private List<FileToConsent> filesToConsent;
    private EIDAuthenticatorInfo eid;
    private WalletAuthenticatorInfo wallet;
    @JsonFormat(pattern="yyyy-MM-dd'T'HH:mm:ss.SSSZ")
    private Date signingDate;
    private RemoteCertificate signingCertificate;
    private List<RemoteCertificate> certificateChain;
}
