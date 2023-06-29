package com.bosa.signingconfigurator.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class PolicyParameters {
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, example = "http://policy.hom.com/policy")
    private String policyId; // EPES. Optional policy fields
    @Schema(example = "Belgium signing Policy")
    private String policyDescription; // EPES. Optional policy fields
    @Schema(example = "SHA256", description = "The digest algorithm used to make the policy digest")
    private DigestAlgorithm policyDigestAlgorithm; // EPES. Optional policy fields

    @JsonIgnore
    public boolean isPolicyValid()
    {
        return policyId != null && policyDigestAlgorithm != null;
    }
}
