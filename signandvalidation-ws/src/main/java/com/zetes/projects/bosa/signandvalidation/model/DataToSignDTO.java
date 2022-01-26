package com.zetes.projects.bosa.signandvalidation.model;

import com.fasterxml.jackson.annotation.JsonFormat;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import lombok.Getter;

import java.util.Date;

@Getter
public class DataToSignDTO {

    private DigestAlgorithm digestAlgorithm;
    private byte[] digest;

    @JsonFormat(pattern="yyyy-MM-dd'T'HH:mm:ss.SSSZ")
    private Date signingDate;

    public DataToSignDTO(DigestAlgorithm digestAlgorithm, byte[] digest, @JsonFormat(pattern = "MMMM d, yyyy") Date signingDate) {
        this.digestAlgorithm = digestAlgorithm;
        this.signingDate = signingDate;
        this.digest = digest;
    }
}
