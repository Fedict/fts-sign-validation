package com.zetes.projects.bosa.signingconfigurator.model;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class PolicyParameters {
    private String policyId; // EPES. Optional policy fields
    private String policyDescription; // EPES. Optional policy fields
    private DigestAlgorithm policyDigestAlgorithm; // EPES. Optional policy fields

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
