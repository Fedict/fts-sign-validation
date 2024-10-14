package com.bosa.signandvalidation.utils;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.validation.RevocationDataLoadingStrategy;
import lombok.NoArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

@NoArgsConstructor
public class OCSPOnlyForLeafRevocationDataLoadingStrategy extends RevocationDataLoadingStrategy {
    private static final Logger LOG = LoggerFactory.getLogger(OCSPOnlyForLeafRevocationDataLoadingStrategy.class);
    @Override
    @SuppressWarnings("rawtypes")
    public RevocationToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerToken) {

        RevocationToken<?> ocspToken = checkOCSP(certificateToken, issuerToken);
        if (ocspToken != null && isAcceptableToken(ocspToken)) {
            return ocspToken;
        }
        if (!isLeafEIDCertificate(certificateToken)) {
            RevocationToken<?> crlToken = checkCRL(certificateToken, issuerToken);
            if (crlToken != null && isAcceptableToken(crlToken)) {
                return crlToken;
            }
            if (ocspToken == null && crlToken == null && LOG.isDebugEnabled()) {
                LOG.debug("There is no response for {} neither from OCSP nor from CRL!", certificateToken.getDSSIdAsString());
            }
            if (fallbackEnabled) {
                // return first successful result
                return ocspToken != null ? ocspToken : crlToken;
            }
        } else {
            LOG.warn("Signature EID Cert, No CRL fallback !!!! - " + certificateToken.getDSSIdAsString());
        }
        return null;
    }

    // As per ETS-553 WE'll identify a leaf signing certificate using the "(Signature)" found in the CN of EID Subject
    private boolean isLeafEIDCertificate(CertificateToken certificateToken) {
        Pattern pattern = Pattern.compile("CN=([^(]+ \\(Signature\\))");
        Matcher matcher = pattern.matcher(certificateToken.getCertificate().getSubjectX500Principal().getName());
        return matcher.find();
    }
}
