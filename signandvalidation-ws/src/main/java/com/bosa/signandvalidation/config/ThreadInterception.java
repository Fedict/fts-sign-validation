package com.bosa.signandvalidation.config;

import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.validation.RevocationDataLoadingStrategyFactory;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;

import java.util.logging.Logger;

public class ThreadInterception extends CommonCertificateVerifier {

    protected final Logger logger = Logger.getLogger(ThreadInterception.class.getName());

    private static final ThreadLocal<CertificateSource> allThreadsExtraTrustSources = new ThreadLocal<CertificateSource>();
    private static final ThreadLocal<RevocationDataLoadingStrategyFactory> allThreadsOverrideRevocationDataLoadingStrategyFactory = new ThreadLocal<RevocationDataLoadingStrategyFactory>();

    public static void setExtraCertificateSource(CertificateSource extraSource) {
        allThreadsExtraTrustSources.set(extraSource);
    }

    public static void setOverrideRevocationDataLoadingStrategyFactory(RevocationDataLoadingStrategyFactory factory) {
        allThreadsOverrideRevocationDataLoadingStrategyFactory.set(factory);
    }

    public static void clearInteceptions() {
        allThreadsOverrideRevocationDataLoadingStrategyFactory.remove();
        allThreadsExtraTrustSources.remove();
    }

    public ListCertificateSource getTrustedCertSources() {
        ListCertificateSource trustedSources = super.getTrustedCertSources();
        CertificateSource extraTrustSource = allThreadsExtraTrustSources.get();
        if (extraTrustSource != null) {
            logger.info("Using Extra trust store for validation");
            // Add a copy of the trusted sources to a new list
            ListCertificateSource currentTrustedSources = trustedSources;
            trustedSources = new ListCertificateSource();
            trustedSources.addAll(currentTrustedSources);
            trustedSources.add(extraTrustSource);
        }

        return trustedSources;
    }

    public RevocationDataLoadingStrategyFactory getRevocationDataLoadingStrategyFactory() {
        RevocationDataLoadingStrategyFactory strategy = allThreadsOverrideRevocationDataLoadingStrategyFactory.get();
        if (strategy == null) strategy = super.getRevocationDataLoadingStrategyFactory();
        return strategy;
    }
}
