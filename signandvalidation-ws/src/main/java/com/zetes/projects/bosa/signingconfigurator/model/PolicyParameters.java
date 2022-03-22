package com.zetes.projects.bosa.signingconfigurator.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import lombok.*;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class PolicyParameters {
    private String policyId; // EPES. Optional policy fields
    private String policyDescription; // EPES. Optional policy fields
    private DigestAlgorithm policyDigestAlgorithm; // EPES. Optional policy fields

    @JsonIgnore
    public boolean isPolicyValid()
    {
        return policyId != null && policyDigestAlgorithm != null;
    }
}
