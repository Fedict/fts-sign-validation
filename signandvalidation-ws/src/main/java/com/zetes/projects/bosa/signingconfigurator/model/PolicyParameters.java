package com.zetes.projects.bosa.signingconfigurator.model;

import com.zetes.projects.bosa.signandvalidation.TokenParser;

public class PolicyParameters {
    private String policyId; // EPES. Optional policy fields
    private String policyDescription; // EPES. Optional policy fields
    private eu.europa.esig.dss.enumerations.DigestAlgorithm policyDigestAlgorithm; // EPES. Optional policy fields

    public PolicyParameters(TokenParser t) {
        this.policyId = t.getPolicyId();
        this.policyDescription = t.getPolicyDescription();
        this.policyDigestAlgorithm = t.getPolicyDigestAlgorithm();
    }

    public String getPolicyId() {
        return policyId;
    }
    public String getPolicyDescription() {
        return policyDescription;
    }
    public eu.europa.esig.dss.enumerations.DigestAlgorithm getPolicyDigestAlgorithm() {
        return policyDigestAlgorithm;
    }

    public boolean IsPolicyValid()
    {
        return policyId != null && policyDigestAlgorithm != null;
    }
}
