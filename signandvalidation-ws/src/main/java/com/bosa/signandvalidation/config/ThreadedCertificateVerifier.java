package com.bosa.signandvalidation.config;

import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;

public class ThreadedCertificateVerifier extends CommonCertificateVerifier {

    private static final ThreadLocal<CertificateSource> allThreadsExtraTrustSources = new ThreadLocal<CertificateSource>();

    public static void setExtraCertificateSource(CertificateSource extraSource) {
        allThreadsExtraTrustSources.set(extraSource);
    }

    public static void clearExtraCertificateSource() {
        allThreadsExtraTrustSources.remove();
    }
    public ListCertificateSource getTrustedCertSources() {
        ListCertificateSource trustedSources = super.getTrustedCertSources();
        CertificateSource extraTrustSource = allThreadsExtraTrustSources.get();
        if (extraTrustSource != null) {
            // Add a copy of the trusted sources to a new list
            ListCertificateSource currentTrustedSources = trustedSources;
            trustedSources = new ListCertificateSource();
            trustedSources.addAll(currentTrustedSources);
            trustedSources.add(extraTrustSource);
        }

        return trustedSources;
    }
}
