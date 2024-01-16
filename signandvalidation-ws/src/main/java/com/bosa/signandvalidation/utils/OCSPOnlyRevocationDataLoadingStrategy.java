package com.bosa.signandvalidation.utils;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.validation.RevocationDataLoadingStrategy;
import lombok.NoArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@NoArgsConstructor
public class OCSPOnlyRevocationDataLoadingStrategy extends RevocationDataLoadingStrategy {
    private static final Logger LOG = LoggerFactory.getLogger(OCSPOnlyRevocationDataLoadingStrategy.class);
    @Override
    @SuppressWarnings("rawtypes")
    public RevocationToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerToken) {
        return this.checkOCSP(certificateToken, issuerToken);
    }
}
