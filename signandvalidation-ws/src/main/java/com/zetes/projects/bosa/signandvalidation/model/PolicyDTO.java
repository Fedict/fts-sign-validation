package com.zetes.projects.bosa.signandvalidation.model;

import com.zetes.projects.bosa.signingconfigurator.model.PolicyParameters;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class PolicyDTO {
    private String id; // EPES. Optional policy fields
    private String description; // EPES. Optional policy fields
    private DigestAlgorithm digestAlgorithm; // EPES. Optional policy fields
}
