package com.bosa.signandvalidation.model;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class PolicyDTO {
    @Schema(requiredMode = Schema.RequiredMode.REQUIRED, example = "http://policy.hom.com/policy")
    private String id;
    @Schema(example = "Belgium signing Policy")
    private String description;
    @Schema(example = "SHA256", description = "The digest algorithm used to make the policy digest")
    private DigestAlgorithm digestAlgorithm;
}
