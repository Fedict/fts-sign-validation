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
    @Schema(description = "Deprecated")
    private String id;
    @Schema(description = "Deprecated")
    private String description;
    @Schema(description = "Deprecated")
    private DigestAlgorithm digestAlgorithm;
}
