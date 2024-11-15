/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.bosa.signandvalidation.model;

import com.bosa.signandvalidation.model.remotesign.DigestsToSign;
import com.fasterxml.jackson.annotation.JsonFormat;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.ws.dto.RemoteDocument;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class RemoteSignDocumentDTO {
    private String signingProfileId;
    private String token;
    private String code;
    private String language;
    private String psfN;
    private String psfC;
    private byte [] photo;
    private PdfSignatureProfile psp;
    private RemoteDocument toSignDocument;

    @Getter
    @NoArgsConstructor
    public static class RemoteDataToSignDTO {
        private List<DigestsToSign> digests = new ArrayList<>();
        @JsonFormat(pattern="yyyy-MM-dd'T'HH:mm:ss.SSSZ")
        private Date signingDate;

        public RemoteDataToSignDTO(Date signingDate) {
            this.signingDate = signingDate;
        }

        public void addDigest(DigestAlgorithm digestAlgorithm, byte[] digest) {
            for(DigestsToSign dts : digests) {
                if (digestAlgorithm.equals(dts.getDigestAlgorithm())) {
                    dts.getDigests().add(digest);
                    return;
                }
            }
            digests.add(new DigestsToSign(digestAlgorithm, digest));
        }
    }
}
