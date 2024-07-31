package com.bosa.signandvalidation.utils;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.validation.RevocationDataLoadingStrategy;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import lombok.NoArgsConstructor;

@NoArgsConstructor
public class OCSPOnlyRevocationDataLoadingStrategy extends RevocationDataLoadingStrategy {
    @Override
    @SuppressWarnings("rawtypes")
    public RevocationToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerToken) {
        return this.checkOCSP(certificateToken, issuerToken);
    }
}
