package com.bosa.signingconfigurator.model;

// As of now only one Strategy supported.
// Default is OCSPFirstRevocationDataLoadingStrategy, but there is also CRLFirstRevocationDataLoadingStrategy
public enum RevocationStrategy {
    DEFAULT,
    OCSP_ONLY,
    OCSP_ONLY_FOR_LEAF
}
