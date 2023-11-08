package com.bosa.signandvalidation.model;

import com.fasterxml.jackson.annotation.JsonFormat;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.Date;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class DataToSignDTO {

    @Schema(description = "The digest algorithm that was used to calculate the digest")
    private DigestAlgorithm digestAlgorithm;

    @Schema(description = "The calculated digest that must be signed")
    private byte[] digest;

    @Schema(description = "The date at which the signature occurred. This is that date at which the digest was calculated.<BR>It must be provided to the signDocument")
    @JsonFormat(pattern="yyyy-MM-dd'T'HH:mm:ss.SSSZ")
    private Date signingDate;
}
