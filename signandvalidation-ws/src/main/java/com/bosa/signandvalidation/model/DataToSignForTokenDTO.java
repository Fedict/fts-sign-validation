/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.bosa.signandvalidation.model;

import com.bosa.signandvalidation.model.remotesign.DigestsToSign;
import com.fasterxml.jackson.annotation.JsonFormat;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Getter
@NoArgsConstructor
public class DataToSignForTokenDTO {
    private List<DigestsToSign> digests = new ArrayList<>();
    @JsonFormat(pattern="yyyy-MM-dd'T'HH:mm:ss.SSSZ")
    private Date signingDate;

    public DataToSignForTokenDTO(Date signingDate) {
        this.signingDate = signingDate;
    }

    public void addDigest(DigestAlgorithm digestAlgorithm, byte[] digest, Integer inputToSignId) {
        for(DigestsToSign dts : digests) {
            if (digestAlgorithm.equals(dts.getDigestAlgorithm())) {
                dts.getDigests().add(digest);
                return;
            }
        }
        digests.add(new DigestsToSign(digestAlgorithm, digest, inputToSignId));
    }
}
